#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::{
    Datastore, ManualActivityEntryV1, SyncApplyBatchV1, SyncDeviceIdentity, SyncKeyMaterial,
    SyncRecoveryTrustedDeviceV1, SyncSnapshotV1,
};
use aw_models::{Bucket, BucketMetadata, BucketsExport, Event, SyncEnvelopeV1, TryVec};
use aw_sync_e2ee::{create_event_correction, DeviceIdentityV1, SyncManifestV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};
use zeroize::Zeroizing;

const BUCKET: &str = "aw-stopwatch-ios-companion";
const CLIENT: &str = "peakactivity-ios-companion";
const HOST: &str = "ios-companion-local";
const FIRST: &str = "01234567-89ab-4cde-8fab-0123456789ab";
const SECOND: &str = "01234567-89ab-4cde-8fab-0123456789ac";
const DEVICE: [u8; 16] = [0x41; 16];
const CHECKPOINT: &str = "ios_manual_source_checkpoint_v1";

#[test]
fn private_source_checkpoint_rejects_invalid_state_without_changing_activity() {
    let f = Fixture::new("checkpoint-invalid");
    let first = entry(FIRST);
    f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    let before = f.events();
    for value in [
        "not-json".to_owned(),
        json!({"schema_version":2,"entries":[]}).to_string(),
        json!({"schema_version":1,"entries":[[FIRST,"bad-digest"]]}).to_string(),
        json!({"schema_version":1,"entries":[[FIRST,"a".repeat(64)],[FIRST,"a".repeat(64)]]})
            .to_string(),
        json!({"schema_version":1,"entries":[],"unknown":true}).to_string(),
    ] {
        f.store.set_key_value(CHECKPOINT, &value).unwrap();
        assert!(f.store.reconcile_manual_entries(&[first.clone()]).is_err());
        assert_eq!(f.events(), before);
        assert_eq!(f.store.get_key_value(CHECKPOINT).unwrap(), value);
    }
}

#[test]
fn private_source_checkpoint_does_not_recreate_deleted_shared_rows_from_unchanged_aes() {
    let f = Fixture::new("checkpoint-deletion");
    f.journal();
    let first = entry(FIRST);
    f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    f.store
        .delete_events_by_id(BUCKET, vec![f.events()[0].id.unwrap()])
        .unwrap();
    let operations = f.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap();
    assert_eq!(
        f.store.reconcile_manual_entries(&[first]).unwrap().inserted,
        0
    );
    assert!(f.events().is_empty());
    assert_eq!(
        f.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap(),
        operations
    );
}

#[test]
fn private_source_checkpoint_does_not_claim_recovered_rows_until_aes_entries_are_supplied() {
    let source = Fixture::new("checkpoint-source");
    source.journal();
    let first = entry(FIRST);
    source
        .store
        .reconcile_manual_entries(&[first.clone()])
        .unwrap();
    let mut exported = source.store.get_bucket(BUCKET).unwrap();
    exported.events = Some(TryVec::new(source.events()));
    let export = BucketsExport {
        buckets: HashMap::from([(BUCKET.into(), exported)]),
    };
    let mut state = source.store.export_sync_recovery_state(1).unwrap();
    let public = DeviceIdentityV1::from_bytes(
        DEVICE,
        Zeroizing::new([0x42; 32]),
        Zeroizing::new([0x43; 32]),
    )
    .public_identity();
    state.trusted_devices.push(SyncRecoveryTrustedDeviceV1 {
        device_id: DEVICE,
        x25519_public_key: URL_SAFE_NO_PAD
            .decode(public.x25519_public_key)
            .unwrap()
            .try_into()
            .unwrap(),
        ed25519_public_key: URL_SAFE_NO_PAD
            .decode(public.ed25519_public_key)
            .unwrap()
            .try_into()
            .unwrap(),
        paired_at: Utc::now().to_rfc3339(),
    });
    let target = Fixture::new("checkpoint-target");
    let snapshot = SyncSnapshotV1::new(
        [0x51; 16],
        vec![SyncEnvelopeV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode([0x52; 16]),
            vault_id: URL_SAFE_NO_PAD.encode([0x45; 16]),
            key_epoch: 1,
            nonce: URL_SAFE_NO_PAD.encode([0x53; 24]),
            ciphertext: URL_SAFE_NO_PAD.encode([0x54; 32]),
        }],
    );
    target
        .store
        .restore_sync_recovery_data(
            export,
            source.store.load_sync_key_material().unwrap().unwrap(),
            snapshot,
            state,
            SyncDeviceIdentity::new(
                [0x61; 16],
                Zeroizing::new([0x62; 32]),
                Zeroizing::new([0x63; 32]),
            ),
        )
        .unwrap();
    assert!(
        target.store.get_key_value(CHECKPOINT).is_err(),
        "source ownership is not part of the recovery payload"
    );
    assert_eq!(
        target.store.reconcile_manual_entries(&[]).unwrap().deleted,
        0
    );
    assert_eq!(target.events().len(), 1);
    let adopted = target.store.reconcile_manual_entries(&[first]).unwrap();
    assert_eq!(
        (adopted.inserted, adopted.corrected, adopted.deleted),
        (0, 0, 0)
    );
    assert_eq!(
        target.store.reconcile_manual_entries(&[]).unwrap().deleted,
        1
    );
}

#[test]
fn private_source_checkpoint_only_adoption_is_durable_and_rolls_back_on_failure() {
    let source = Fixture::new("checkpoint-adoption-source");
    let first = entry(FIRST);
    source
        .store
        .reconcile_manual_entries(&[first.clone()])
        .unwrap();
    let mut target = Fixture::new("checkpoint-adoption-target");
    target
        .store
        .create_bucket(&bucket(BUCKET, CLIENT, source.events()))
        .unwrap();
    target.store.lock().unwrap();
    let conn = rusqlite::Connection::open(&target.path).unwrap();
    conn.pragma_update(None, "key", &target.key).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON key_value WHEN NEW.key = 'ios_manual_source_checkpoint_v1' BEGIN SELECT RAISE(ABORT,'synthetic checkpoint failure'); END;").unwrap();
    drop(conn);
    target.store = Datastore::open_encrypted(
        target.path.to_string_lossy().into_owned(),
        target.key.clone(),
    )
    .unwrap();
    target.store.enable_capture_policy().unwrap();
    assert!(target
        .store
        .reconcile_manual_entries(&[first.clone()])
        .is_err());
    assert!(target.store.get_key_value(CHECKPOINT).is_err());
    assert_eq!(target.events().len(), 1);
    target.store.lock().unwrap();
    let conn = rusqlite::Connection::open(&target.path).unwrap();
    conn.pragma_update(None, "key", &target.key).unwrap();
    conn.execute_batch("DROP TRIGGER reject_checkpoint")
        .unwrap();
    drop(conn);
    target.store = Datastore::open_encrypted(
        target.path.to_string_lossy().into_owned(),
        target.key.clone(),
    )
    .unwrap();
    target.store.enable_capture_policy().unwrap();
    let adopted = target.store.reconcile_manual_entries(&[first]).unwrap();
    assert_eq!(
        (adopted.inserted, adopted.corrected, adopted.deleted),
        (0, 0, 0)
    );
    target.reopen();
    assert_eq!(
        target.store.reconcile_manual_entries(&[]).unwrap().deleted,
        1
    );
}

struct Fixture {
    store: Datastore,
    path: PathBuf,
    key: String,
}
impl Fixture {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "manual-{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = "ab".repeat(32);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        store.enable_capture_policy().unwrap();
        Self { store, path, key }
    }
    fn reopen(&mut self) {
        self.store.lock().unwrap();
        self.store =
            Datastore::open_encrypted(self.path.to_string_lossy().into_owned(), self.key.clone())
                .unwrap();
        self.store.enable_capture_policy().unwrap();
    }
    fn journal(&self) -> u64 {
        self.store
            .create_sync_device_identity(&SyncDeviceIdentity::new(
                DEVICE,
                Zeroizing::new([0x42; 32]),
                Zeroizing::new([0x43; 32]),
            ))
            .unwrap();
        self.store
            .install_sync_key_material(&SyncKeyMaterial::new(
                Zeroizing::new([0x44; 32]),
                [0x45; 16],
                1,
                [0x46; 24],
                [0x47; 48],
            ))
            .unwrap();
        self.store.begin_sync_baseline().unwrap();
        let seed_cursor = self.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap().last().unwrap().counter;
        assert!(self.store.process_sync_baseline_batch(1).unwrap().complete);
        seed_cursor
    }
    fn events(&self) -> Vec<Event> {
        self.store
            .get_events_unclipped(BUCKET, None, None, None)
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.store.lock();
        let _ = std::fs::remove_file(&self.path);
    }
}
fn entry(id: &str) -> ManualActivityEntryV1 {
    serde_json::from_value(
        json!({"id":id,"timestamp":"2026-10-12T12:00:00Z","duration_seconds":60}),
    )
    .unwrap()
}
fn bucket(id: &str, client: &str, events: Vec<Event>) -> Bucket {
    Bucket {
        bid: None,
        id: id.into(),
        _type: "general.stopwatch".into(),
        client: client.into(),
        hostname: HOST.into(),
        created: None,
        data: Default::default(),
        metadata: BucketMetadata::default(),
        events: Some(TryVec::new(events)),
        last_updated: None,
    }
}

#[test]
fn strict_snapshot_rejects_private_fields_duplicates_and_invalid_ranges_without_mutation() {
    let f = Fixture::new("invalid");
    let first = entry(FIRST);
    let input = serde_json::to_value(&first).unwrap();
    let mut private = input.clone();
    private["note"] = json!("Never leaves the AES companion vault");
    assert!(serde_json::from_value::<ManualActivityEntryV1>(private).is_err());
    for invalid in [json!("not-a-uuid"), json!(null)] {
        let mut bad = input.clone();
        bad["id"] = invalid;
        assert!(serde_json::from_value::<ManualActivityEntryV1>(bad).is_err());
    }
    for invalid in [json!(0), json!(86401), json!(-1), json!(1.5)] {
        let mut bad = input.clone();
        bad["duration_seconds"] = invalid;
        assert!(serde_json::from_value::<ManualActivityEntryV1>(bad).is_err());
    }
    for invalid in [
        json!("2026-10-12 12:00:00+0000"),
        json!("not-a-date"),
        json!(null),
    ] {
        let mut bad = input.clone();
        bad["timestamp"] = invalid;
        assert!(serde_json::from_value::<ManualActivityEntryV1>(bad).is_err());
    }
    assert!(f
        .store
        .reconcile_manual_entries(&[first.clone(), first.clone()])
        .is_err());
    let mut overflow = first.clone();
    overflow.timestamp = "2262-04-11T23:47:16.854775Z".parse().unwrap();
    assert!(f
        .store
        .reconcile_manual_entries(&[first.clone(), overflow])
        .is_err());
    let too_many = (0..10001)
        .map(|n| entry(&format!("00000000-0000-4000-8000-{n:012x}")))
        .collect::<Vec<_>>();
    assert!(f.store.reconcile_manual_entries(&too_many).is_err());
    assert!(f.store.get_bucket(BUCKET).is_err());
    f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    assert!(f
        .store
        .reconcile_manual_entries(&[entry(SECOND), first.clone(), first])
        .is_err());
    assert_eq!(f.events().len(), 1);
}

#[test]
fn future_manual_rows_are_durable_idempotent_and_journalled_through_delete() {
    let mut f = Fixture::new("journal");
    let seed_cursor = f.journal();
    let mut first = entry(&FIRST.to_uppercase());
    first.timestamp = Utc::now() + Duration::days(1);
    let result = f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    assert_eq!(
        (
            result.inserted,
            result.corrected,
            result.deleted,
            result.filtered
        ),
        (1, 0, 0, 0)
    );
    let stored = f.events().pop().unwrap();
    assert_eq!(stored.data["manual_entry_id"], FIRST);
    assert_eq!(stored.data["label"], "Manual activity");
    assert_eq!(stored.data["running"], false);
    assert_eq!(stored.data.len(), 4);
    assert_eq!(stored.duration, Duration::seconds(60));
    assert_eq!(
        f.store
            .list_sync_operations(DEVICE, 1, seed_cursor, 256)
            .unwrap()
            .len(),
        1
    );
    f.reopen();
    let result = f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    assert_eq!(
        (result.inserted, result.corrected, result.deleted),
        (0, 0, 0)
    );
    assert_eq!(f.events()[0].id, stored.id);
    assert_eq!(
        f.store
            .list_sync_operations(DEVICE, 1, seed_cursor, 256)
            .unwrap()
            .len(),
        1
    );
    first.duration_seconds = 120;
    assert_eq!(
        f.store
            .reconcile_manual_entries(&[first])
            .unwrap()
            .corrected,
        1
    );
    assert_eq!(f.store.reconcile_manual_entries(&[]).unwrap().deleted, 1);
    assert!(f.events().is_empty());
    let operations = f.store.list_sync_operations(DEVICE, 1, seed_cursor, 256).unwrap();
    assert_eq!(operations.len(), 3);
    assert!(operations[0].operation_json.contains(FIRST));
    assert!(operations[0]
        .operation_json
        .contains("manual_source_sha256"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&operations[2].operation_json).unwrap()["kind"],
        "tombstone"
    );
    assert!(!operations
        .iter()
        .any(|op| op.operation_json.contains("note")));
}

#[test]
fn privacy_drops_cannot_turn_present_snapshot_ids_into_deletions() {
    let f = Fixture::new("privacy");
    let first = entry(FIRST);
    let second = entry(SECOND);
    f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    let original = f.events()[0].clone();
    f.store.set_key_value("settings.privacy_filters",&json!([{
        "enabled":true,"bucket_prefix":BUCKET,"field":"label","pattern":"Manual activity","action":"drop","replacement":null
    }]).to_string()).unwrap();
    let result = f.store.reconcile_manual_entries(&[first, second]).unwrap();
    assert_eq!(
        (
            result.inserted,
            result.corrected,
            result.deleted,
            result.filtered
        ),
        (0, 0, 0, 2)
    );
    assert_eq!(f.events(), vec![original]);
}

#[test]
fn projection_never_claims_desktop_remote_or_unmanaged_events() {
    let f = Fixture::new("isolation");
    let desktop = Event::new(
        Utc::now(),
        Duration::seconds(30),
        json!({"label":"Desktop","running":false})
            .as_object()
            .unwrap()
            .clone(),
    );
    let remote = Event::new(Utc::now(),Duration::seconds(40),json!({"label":"Manual activity","running":false,"manual_entry_id":FIRST,"manual_source_sha256":"ab".repeat(32)}).as_object().unwrap().clone());
    f.store
        .restore_sync_snapshot_data(BucketsExport {
            buckets: HashMap::from([
                (
                    "aw-stopwatch".into(),
                    bucket("aw-stopwatch", "aw-webui", vec![desktop.clone()]),
                ),
                (
                    "aw-sync-remote".into(),
                    bucket("aw-sync-remote", CLIENT, vec![remote.clone()]),
                ),
            ]),
        })
        .unwrap();
    f.store.reconcile_manual_entries(&[entry(FIRST)]).unwrap();
    f.store.import_events(BUCKET, &[desktop.clone()]).unwrap();
    f.store.reconcile_manual_entries(&[]).unwrap();
    assert_eq!(f.events(), vec![desktop.clone()]);
    assert_eq!(
        f.store
            .get_events_unclipped("aw-stopwatch", None, None, None)
            .unwrap(),
        vec![desktop]
    );
    assert_eq!(
        f.store
            .get_events_unclipped("aw-sync-remote", None, None, None)
            .unwrap(),
        vec![remote]
    );
    let other = Fixture::new("wrong-owner");
    other
        .store
        .create_bucket(&bucket(BUCKET, "aw-webui", vec![]))
        .unwrap();
    assert!(other
        .store
        .reconcile_manual_entries(&[entry(FIRST)])
        .is_err());
    assert!(other.events().is_empty());
}

#[test]
fn unchanged_source_digest_preserves_peer_timing_then_local_edit_updates_it() {
    let f = Fixture::new("convergence");
    f.journal();
    let first = entry(FIRST);
    f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    let original = f.events()[0].clone();
    let signer = DeviceIdentityV1::from_bytes(
        [0x51; 16],
        Zeroizing::new([0x52; 32]),
        Zeroizing::new([0x53; 32]),
    );
    let public = signer.public_identity();
    f.store
        .record_sync_pairing(
            None,
            [0x54; 16],
            [0x51; 16],
            URL_SAFE_NO_PAD
                .decode(public.x25519_public_key)
                .unwrap()
                .try_into()
                .unwrap(),
            URL_SAFE_NO_PAD
                .decode(public.ed25519_public_key)
                .unwrap()
                .try_into()
                .unwrap(),
            Utc::now().to_rfc3339(),
        )
        .unwrap();
    let state = f.store.export_sync_recovery_state(1).unwrap();
    let mapping = state
        .event_mappings
        .iter()
        .find(|m| m.local_event_id == Some(original.id.unwrap() as u64))
        .unwrap();
    let correction = create_event_correction(
        [0x51; 16],
        f.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap().last().unwrap().counter + 1,
        mapping.origin_device_id,
        mapping.origin_event_id,
        mapping.sync_bucket_id,
        BTreeMap::from([("duration_ns".into(), json!(180_000_000_000u64))]),
    )
    .unwrap();
    let manifest =
        SyncManifestV1::new_signed(&signer, [0x45; 16], 1, 1, [0; 32], vec![correction]).unwrap();
    f.store
        .apply_sync_operations(SyncApplyBatchV1 { manifest })
        .unwrap();
    let peer = f.events()[0].clone();
    assert_eq!(peer.duration, Duration::seconds(180));
    let operations = f.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap();
    let result = f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    assert_eq!(
        (result.inserted, result.corrected, result.deleted),
        (0, 0, 0)
    );
    assert_eq!(f.events()[0], peer);
    assert_eq!(
        f.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap(),
        operations
    );
    let mut edited = first;
    edited.duration_seconds = 120;
    assert_eq!(
        f.store
            .reconcile_manual_entries(&[edited])
            .unwrap()
            .corrected,
        1
    );
    assert_eq!(f.events()[0].duration, Duration::seconds(120));
    assert_ne!(
        f.events()[0].data["manual_source_sha256"],
        peer.data["manual_source_sha256"]
    );
}

#[test]
fn uuid_and_source_digest_survive_typed_recovery_and_reopened_index_rebuild() {
    let source = Fixture::new("recovery-source");
    source.journal();
    let first = entry(FIRST);
    source
        .store
        .reconcile_manual_entries(&[first.clone()])
        .unwrap();
    let saved = source.events()[0].clone();
    let mut exported = source.store.get_bucket(BUCKET).unwrap();
    exported.events = Some(TryVec::new(vec![saved.clone()]));
    let source_operations = source.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap();
    let mut state = source.store.export_sync_recovery_state(1).unwrap();
    let original = DeviceIdentityV1::from_bytes(
        DEVICE,
        Zeroizing::new([0x42; 32]),
        Zeroizing::new([0x43; 32]),
    )
    .public_identity();
    state.trusted_devices.push(SyncRecoveryTrustedDeviceV1 {
        device_id: DEVICE,
        x25519_public_key: URL_SAFE_NO_PAD
            .decode(original.x25519_public_key)
            .unwrap()
            .try_into()
            .unwrap(),
        ed25519_public_key: URL_SAFE_NO_PAD
            .decode(original.ed25519_public_key)
            .unwrap()
            .try_into()
            .unwrap(),
        paired_at: Utc::now().to_rfc3339(),
    });
    let mut restored = Fixture::new("recovery-target");
    restored
        .store
        .restore_sync_recovery_data(
            BucketsExport {
                buckets: HashMap::from([(BUCKET.into(), exported)]),
            },
            SyncKeyMaterial::new(
                Zeroizing::new([0x44; 32]),
                [0x45; 16],
                1,
                [0x46; 24],
                [0x47; 48],
            ),
            SyncSnapshotV1::new(
                [0x71; 16],
                vec![SyncEnvelopeV1 {
                    schema_version: 1,
                    object_id: URL_SAFE_NO_PAD.encode([0x72; 16]),
                    vault_id: URL_SAFE_NO_PAD.encode([0x45; 16]),
                    key_epoch: 1,
                    nonce: URL_SAFE_NO_PAD.encode([0x73; 24]),
                    ciphertext: URL_SAFE_NO_PAD.encode([0x74; 32]),
                }],
            ),
            state,
            SyncDeviceIdentity::new(
                [0x61; 16],
                Zeroizing::new([0x62; 32]),
                Zeroizing::new([0x63; 32]),
            ),
        )
        .unwrap();
    restored.reopen();
    let result = restored.store.reconcile_manual_entries(&[first]).unwrap();
    assert_eq!(
        (result.inserted, result.corrected, result.deleted),
        (0, 0, 0)
    );
    assert_eq!(restored.events()[0].data, saved.data);
    let recovered_operations = restored.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap();
    assert_eq!(recovered_operations.iter().filter(|op| serde_json::from_str::<aw_sync_e2ee::SyncOperationV1>(&op.operation_json).unwrap().kind != aw_models::SyncOperationKindV1::PolicyChange).count(), 1);
    assert_eq!(recovered_operations, source_operations);
    assert!(restored
        .store
        .list_sync_operations([0x61; 16], 1, 0, 16)
        .unwrap()
        .is_empty());
}

#[test]
fn legacy_projection_can_seed_digest_only_when_local_snapshot_matches() {
    let f = Fixture::new("legacy");
    let first = entry(FIRST);
    let legacy = Event::new(
        first.timestamp,
        Duration::seconds(60),
        json!({"label":"Manual activity","running":false,"manual_entry_id":FIRST})
            .as_object()
            .unwrap()
            .clone(),
    );
    f.store
        .create_bucket(&bucket(BUCKET, CLIENT, vec![legacy]))
        .unwrap();
    let mut divergent = first.clone();
    divergent.duration_seconds = 120;
    assert!(f
        .store
        .reconcile_manual_entries(&[entry(SECOND), divergent])
        .is_err());
    assert_eq!(f.events().len(), 1);
    assert!(!f.events()[0].data.contains_key("manual_source_sha256"));
    assert_eq!(
        f.store
            .reconcile_manual_entries(&[first])
            .unwrap()
            .corrected,
        1
    );
    assert!(f.events()[0].data.contains_key("manual_source_sha256"));
}

#[test]
fn failed_second_insert_rolls_back_bucket_cache_and_sync_journal() {
    let mut f = Fixture::new("rollback");
    f.journal();
    let seed_history = f.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap();
    f.store.lock().unwrap();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    db.pragma_update(None, "key", &f.key).unwrap();
    db.execute_batch(&format!("CREATE TRIGGER fail_manual_insert BEFORE INSERT ON events WHEN instr(NEW.data,'{SECOND}')>0 BEGIN SELECT RAISE(ABORT,'synthetic projection failure'); END;")).unwrap();
    drop(db);
    f.store =
        Datastore::open_encrypted(f.path.to_string_lossy().into_owned(), f.key.clone()).unwrap();
    f.store.enable_capture_policy().unwrap();
    assert!(f
        .store
        .reconcile_manual_entries(&[entry(FIRST), entry(SECOND)])
        .is_err());
    assert!(f.store.get_bucket(BUCKET).is_err());
    assert_eq!(f.store.list_sync_operations(DEVICE, 1, 0, 256).unwrap(), seed_history);
    assert_eq!(
        f.store
            .reconcile_manual_entries(&[entry(FIRST)])
            .unwrap()
            .inserted,
        1
    );
    assert_eq!(f.events().len(), 1);
}

fn drop_rule(prefix: &str, field: &str, pattern: &str) -> String {
    json!([{"enabled":true,"bucket_prefix":prefix,"field":field,"pattern":pattern,"action":"drop","replacement":null}]).to_string()
}

#[test]
fn privacy_setting_changes_apply_to_ordinary_writes_and_invalid_updates_preserve_rules() {
    let f = Fixture::new("live-privacy");
    let id = "aw-watcher-window_privacy";
    let mut source = bucket(id, "test", vec![]);
    source._type = "currentwindow".into();
    f.store.create_bucket(&source).unwrap();
    let mut policy = f.store.capture_policy().unwrap();
    policy.recording = true;
    f.store.set_capture_policy(policy).unwrap();
    let window = || {
        Event::new(
            Utc::now(),
            Duration::zero(),
            json!({"app":"Editor"}).as_object().unwrap().clone(),
        )
    };
    let rules = drop_rule("aw-watcher-window_", "app", "Editor");
    f.store
        .set_key_value("settings.privacy_filters", &rules)
        .unwrap();
    assert!(f.store.insert_events(id, &[window()]).unwrap().is_empty());
    assert!(f
        .store
        .heartbeat(id, window(), 100.0)
        .unwrap()
        .data
        .is_empty());
    assert!(!f
        .store
        .compare_and_set_key_value("settings.privacy_filters", None, Some("invalid JSON"))
        .unwrap());
    assert!(f
        .store
        .set_key_value("settings.privacy_filters", &drop_rule(id, "app", "["))
        .is_err());
    assert!(f
        .store
        .compare_and_set_key_value(
            "settings.privacy_filters",
            Some(&rules),
            Some("invalid JSON")
        )
        .is_err());
    assert_eq!(
        f.store.get_key_value("settings.privacy_filters").unwrap(),
        rules
    );
    assert!(f.store.insert_events(id, &[window()]).unwrap().is_empty());
    assert!(f
        .store
        .compare_and_set_key_value("settings.privacy_filters", Some(&rules), Some("[]"))
        .unwrap());
    assert_eq!(f.store.insert_events(id, &[window()]).unwrap().len(), 1);
    f.store
        .set_key_value("settings.privacy_filters", &rules)
        .unwrap();
    f.store
        .delete_key_value("settings.privacy_filters")
        .unwrap();
    f.store.heartbeat(id, window(), 100.0).unwrap();
    assert_eq!(
        f.store
            .get_events_unclipped(id, None, None, None)
            .unwrap()
            .len(),
        2,
        "A rules change must break heartbeat merging"
    );
    f.store
        .set_key_value("settings.privacy_filters", &rules)
        .unwrap();
    f.store.reset_privacy().unwrap();
    assert_eq!(f.store.import_events(id, &[window()]).unwrap().len(), 1);
}

#[test]
fn reopening_loads_privacy_before_capture_toggle_and_invalid_saved_rules_fail_closed() {
    let mut f = Fixture::new("startup-privacy");
    let first = entry(FIRST);
    f.store.reconcile_manual_entries(&[first.clone()]).unwrap();
    let saved = f.events();
    let rules = drop_rule(BUCKET, "label", "Manual activity");
    f.store
        .set_key_value("settings.privacy_filters", &rules)
        .unwrap();
    f.store.lock().unwrap();
    f.store =
        Datastore::open_encrypted(f.path.to_string_lossy().into_owned(), f.key.clone()).unwrap();
    assert!(f.store.capture_policy().is_err());
    assert_eq!(
        f.store.reconcile_manual_entries(&[first]).unwrap().filtered,
        1
    );
    assert_eq!(f.events(), saved);
    f.store.lock().unwrap();
    let db = rusqlite::Connection::open(&f.path).unwrap();
    db.pragma_update(None, "key", &f.key).unwrap();
    db.execute(
        "UPDATE key_value SET value='invalid JSON' WHERE key='settings.privacy_filters'",
        [],
    )
    .unwrap();
    drop(db);
    assert!(
        Datastore::open_encrypted(f.path.to_string_lossy().into_owned(), f.key.clone()).is_err()
    );
    let db = rusqlite::Connection::open(&f.path).unwrap();
    db.pragma_update(None, "key", &f.key).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM events", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
