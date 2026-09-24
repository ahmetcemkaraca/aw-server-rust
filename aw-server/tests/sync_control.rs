use aw_datastore::{Datastore, SyncDeviceIdentity, SyncKeyMaterial, SyncManifestHeadV1};
use aw_models::{Bucket, BucketMetadata, Event, SyncBucketDescriptorV1, SyncChunkHeaderV1, SyncEnvelopeV1, TryVec};
use aw_server::sync_control::SyncControl;
use aw_sync_e2ee::{
    create_event_upsert, create_vault_data_key, decrypt_manifest, decrypt_snapshot, encrypt_manifest,
    generate_account_root_key, open_recovery_kit, unwrap_vault_data_key, DeviceIdentityV1,
    EncryptedSyncSnapshotV1, SyncManifestV1,
    SyncObjectStoreErrorV1, SyncObjectStoreV1, VaultDataKeyV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Default)]
struct CountingSyncStore {
    envelopes: Mutex<BTreeMap<String, SyncEnvelopeV1>>,
    requests: AtomicUsize,
    fail_put: bool,
}

impl CountingSyncStore {
    fn new(fail_put: bool) -> Self {
        Self { envelopes: Mutex::new(BTreeMap::new()), requests: AtomicUsize::new(0), fail_put }
    }

    fn request_count(&self) -> usize { self.requests.load(Ordering::Relaxed) }
}

impl SyncObjectStoreV1 for CountingSyncStore {
    fn put_if_absent(&self, envelope: &SyncEnvelopeV1) -> Result<bool, SyncObjectStoreErrorV1> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if self.fail_put { return Err(SyncObjectStoreErrorV1::TransportUnavailable); }
        envelope.validate().map_err(|_| SyncObjectStoreErrorV1::InvalidEnvelope)?;
        let mut objects = self.envelopes.lock().map_err(|_| SyncObjectStoreErrorV1::Io)?;
        match objects.get(&envelope.object_id) {
            Some(stored) if stored == envelope => Ok(false),
            Some(_) => Err(SyncObjectStoreErrorV1::ObjectConflict),
            None => { objects.insert(envelope.object_id.clone(), envelope.clone()); Ok(true) }
        }
    }

    fn get(&self, object_id: &str) -> Result<Option<SyncEnvelopeV1>, SyncObjectStoreErrorV1> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        Ok(self.envelopes.lock().map_err(|_| SyncObjectStoreErrorV1::Io)?.get(object_id).cloned())
    }

    fn list_opaque_heads(&self, vault_id: &str) -> Result<Vec<SyncEnvelopeV1>, SyncObjectStoreErrorV1> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        Ok(self.envelopes.lock().map_err(|_| SyncObjectStoreErrorV1::Io)?
            .values().filter(|envelope| envelope.vault_id == vault_id).cloned().collect())
    }

    fn delete_after_tombstone(
        &self,
        _: &aw_sync_e2ee::SyncTombstoneDeletionPermitV1,
    ) -> Result<bool, SyncObjectStoreErrorV1> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        Ok(false)
    }
}

struct PairedDevices {
    first: Datastore,
    second: Datastore,
    first_control: SyncControl,
    second_control: SyncControl,
    first_id: [u8; 16],
    second_id: [u8; 16],
    vault_id: [u8; 16],
    data_key: VaultDataKeyV1,
}

fn create_bucket(store: &Datastore, bucket_id: &str, client: &str, title: &str) {
    store.create_bucket(&Bucket {
        bid: None,
        id: bucket_id.into(),
        _type: "app".into(),
        client: client.into(),
        hostname: "host".into(),
        created: None,
        data: Default::default(),
        metadata: BucketMetadata::default(),
        events: Some(TryVec::new(vec![Event::new(
            Utc::now(), Duration::seconds(2),
            json!({"app":client,"title":title}).as_object().unwrap().clone(),
        )])),
        last_updated: None,
    }).unwrap();
}

fn enable_test_recording(store: &Datastore) {
    let mut policy = store.capture_policy().unwrap_or_else(|_| store.enable_capture_policy().unwrap());
    policy.recording = true;
    policy.titles = true;
    store.set_capture_policy(policy).unwrap();
}

fn paired_devices(root: &std::path::Path) -> PairedDevices {
    let vault_id = [0x71; 16];
    let account_root = generate_account_root_key().unwrap();
    let (data_key, wrapped) = create_vault_data_key(
        &account_root, &URL_SAFE_NO_PAD.encode(vault_id), 1,
    ).unwrap();
    let material = SyncKeyMaterial::new(
        account_root.secret_for_storage(),
        vault_id,
        1,
        URL_SAFE_NO_PAD.decode(&wrapped.nonce).unwrap().try_into().unwrap(),
        URL_SAFE_NO_PAD.decode(&wrapped.ciphertext).unwrap().try_into().unwrap(),
    );
    let first_id = [0x11; 16];
    let second_id = [0x22; 16];
    let first_identity = DeviceIdentityV1::from_bytes(first_id, Zeroizing::new([0x31; 32]), Zeroizing::new([0x41; 32]));
    let second_identity = DeviceIdentityV1::from_bytes(second_id, Zeroizing::new([0x32; 32]), Zeroizing::new([0x42; 32]));
    let first = Datastore::open_encrypted(root.join("first.db").to_string_lossy().into_owned(), "pair-first-key-".repeat(4)).unwrap();
    let second = Datastore::open_encrypted(root.join("second.db").to_string_lossy().into_owned(), "pair-second-key".repeat(4)).unwrap();
    first.create_sync_device_identity(&SyncDeviceIdentity::new(first_id, first_identity.secret_for_storage(), first_identity.signing_seed_for_storage())).unwrap();
    second.create_sync_device_identity(&SyncDeviceIdentity::new(second_id, second_identity.secret_for_storage(), second_identity.signing_seed_for_storage())).unwrap();
    first.install_sync_key_material(&material).unwrap();
    second.install_sync_key_material(&material).unwrap();
    let first_peer = second_identity.public_identity();
    let second_peer = first_identity.public_identity();
    let public_key = |value: &str| URL_SAFE_NO_PAD.decode(value).unwrap().try_into().unwrap();
    let at = "2026-09-23T12:00:00Z".to_owned();
    first.record_sync_pairing(None, [0x51; 16], second_id, public_key(&first_peer.x25519_public_key), public_key(&first_peer.ed25519_public_key), at.clone()).unwrap();
    second.record_sync_pairing(None, [0x52; 16], first_id, public_key(&second_peer.x25519_public_key), public_key(&second_peer.ed25519_public_key), at.clone()).unwrap();
    first.confirm_sync_recovery_saved(at.clone()).unwrap();
    second.confirm_sync_recovery_saved(at).unwrap();
    create_bucket(&first, "local-a", "client-a", "event-a");
    create_bucket(&second, "local-b", "client-b", "event-b");
    let first_control = SyncControl::new();
    let second_control = SyncControl::new();
    first_control.invoke(&first, "create_current_sync_snapshot", json!({})).unwrap();
    second_control.invoke(&second, "create_current_sync_snapshot", json!({})).unwrap();

    PairedDevices {
        first,
        second,
        first_control,
        second_control,
        first_id,
        second_id,
        vault_id,
        data_key,
    }
}

fn finish_baseline(store: &Datastore) {
    let mut progress = store.begin_sync_baseline().unwrap();
    while !progress.complete { progress = store.process_sync_baseline_batch(64).unwrap(); }
}

#[test]
fn local_identity_and_recovery_kit_require_explicit_confirmation() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-control-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let database = root.join("sqlite.db");
    let store = Datastore::open_encrypted(database.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let control = SyncControl::new();

    let identity = control.invoke(&store, "create_local_sync_identity", json!({})).unwrap();
    assert_eq!(identity["schema_version"], 1);
    assert!(!identity["device_id"].as_str().unwrap().is_empty());
    let devices = control.invoke(&store, "list_sync_devices", json!({})).unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 1);
    assert_eq!(devices[0]["is_current_device"], true);

    let recovery = control.invoke(&store, "create_sync_recovery_kit", json!({})).unwrap();
    assert!(!recovery["recovery_phrase"].as_str().unwrap().is_empty());
    let preview = control.invoke(&store, "verify_sync_recovery_kit", json!({
        "kit": recovery["kit"].clone(),
        "recoveryPhrase": recovery["recovery_phrase"],
    })).unwrap();
    assert!(!preview["vault_id"].as_str().unwrap().is_empty());
    assert!(control.invoke(&store, "create_sync_recovery_kit", json!({})).is_err());
    assert!(control.invoke(&store, "confirm_sync_recovery_saved", json!({"userConfirmed": false})).is_err());
    control.invoke(&store, "confirm_sync_recovery_saved", json!({"userConfirmed": true})).unwrap();
    assert_eq!(control.invoke(&store, "sync_recovery_confirmed", json!({})).unwrap(), true);
    assert!(control.invoke(&store, "create_sync_recovery_kit", json!({})).is_err());

    store.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn device_pairing_requires_matching_verification_and_transfers_encrypted_keys() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-pairing-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let first = Datastore::open_encrypted(root.join("first.db").to_string_lossy().into_owned(), "b".repeat(64)).unwrap();
    let second = Datastore::open_encrypted(root.join("second.db").to_string_lossy().into_owned(), "c".repeat(64)).unwrap();
    let first_control = SyncControl::new();
    let second_control = SyncControl::new();

    let first_identity = first_control.invoke(&first, "create_local_sync_identity", json!({})).unwrap();
    let second_identity = second_control.invoke(&second, "create_local_sync_identity", json!({})).unwrap();
    let invitation = first_control.invoke(&first, "create_sync_pairing", json!({"recipient": second_identity})).unwrap();
    let response = second_control.invoke(&second, "respond_sync_pairing", json!({"invitation": invitation})).unwrap();
    let display = first_control.invoke(&first, "complete_sync_pairing", json!({"response": response})).unwrap();
    let code = second_control.invoke(&second, "prepare_sync_pairing", json!({"offer": display["offer"]})).unwrap();
    assert_eq!(display["verification_code"], code);

    let first_confirmation = first_control.invoke(&first, "confirm_sync_pairing", json!({
        "displayedCode": display["verification_code"], "userConfirmed": true,
    })).unwrap();
    let second_confirmation = second_control.invoke(&second, "confirm_sync_pairing", json!({
        "displayedCode": code, "userConfirmed": true,
    })).unwrap();
    let transfer = first_control.invoke(&first, "create_sync_key_transfer", json!({
        "peerConfirmation": second_confirmation,
    })).unwrap();
    let paired_peer = second_control.invoke(&second, "accept_sync_key_transfer", json!({
        "peerConfirmation": first_confirmation, "transfer": transfer,
    })).unwrap();

    assert_eq!(paired_peer["device_id"], first_identity["device_id"]);
    assert_eq!(first_control.invoke(&first, "list_sync_devices", json!({})).unwrap().as_array().unwrap().len(), 2);
    assert_eq!(second_control.invoke(&second, "list_sync_devices", json!({})).unwrap().as_array().unwrap().len(), 2);

    first.close();
    second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rotation_builds_a_verified_encrypted_snapshot_before_export() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-snapshot-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let store = Datastore::open_encrypted(root.join("sqlite.db").to_string_lossy().into_owned(), "f".repeat(64)).unwrap();
    let control = SyncControl::new();
    control.invoke(&store, "create_sync_recovery_kit", json!({})).unwrap();
    control.invoke(&store, "confirm_sync_recovery_saved", json!({"userConfirmed": true})).unwrap();

    let created = control.invoke(&store, "create_current_sync_snapshot", json!({})).unwrap();
    assert_eq!(created["key_epoch"], 1);
    let first_export = control.invoke(&store, "export_sync_snapshot", json!({})).unwrap();
    assert_eq!(control.invoke(&store, "export_sync_snapshot", json!({})).unwrap(), first_export);

    let epoch = control.invoke(&store, "rotate_sync_keys", json!({})).unwrap();
    assert_eq!(epoch.as_u64(), Some(2));
    assert_eq!(control.invoke(&store, "sync_recovery_confirmed", json!({})).unwrap(), false);
    control.invoke(&store, "create_sync_recovery_kit", json!({})).unwrap();
    control.invoke(&store, "confirm_sync_recovery_saved", json!({"userConfirmed": true})).unwrap();
    let snapshot = control.invoke(&store, "export_sync_snapshot", json!({})).unwrap();
    let retry = control.invoke(&store, "export_sync_snapshot", json!({})).unwrap();
    assert_eq!(retry, snapshot);
    assert_eq!(snapshot["schema_version"], 1);
    assert!(!snapshot["envelopes"].as_array().unwrap().is_empty());
    assert_eq!(control.invoke(&store, "sync_recovery_confirmed", json!({})).unwrap(), true);

    store.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restore_requires_acceptance_and_commits_activity_keys_and_snapshot_together() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-restore-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let source = Datastore::open_encrypted(root.join("source.db").to_string_lossy().into_owned(), "1".repeat(64)).unwrap();
    let target = Datastore::open_encrypted(root.join("target.db").to_string_lossy().into_owned(), "2".repeat(64)).unwrap();
    enable_test_recording(&target);
    target.pause_capture().unwrap();
    let control = SyncControl::new();
    let source_id = [0x64; 16];
    let source_identity = DeviceIdentityV1::from_bytes(
        source_id, Zeroizing::new([0x74; 32]), Zeroizing::new([0x84; 32]),
    );
    source.create_sync_device_identity(&SyncDeviceIdentity::new(
        source_id, source_identity.secret_for_storage(), source_identity.signing_seed_for_storage(),
    )).unwrap();
    create_bucket(&source, "local-a", "client-a", "recovered-event");
    create_bucket(&source, "local-tombstone", "client-b", "deleted-event");
    let kit = control.invoke(&source, "create_sync_recovery_kit", json!({})).unwrap();
    control.invoke(&source, "confirm_sync_recovery_saved", json!({"userConfirmed": true})).unwrap();
    finish_baseline(&source);
    let deleted_event = source.get_events("local-tombstone", None, None, None).unwrap().remove(0);
    source.delete_events_by_id("local-tombstone", vec![deleted_event.id.unwrap()]).unwrap();
    let source_operations = source.list_sync_operations(source_id, 1, 0, 16).unwrap();
    assert_eq!(source_operations.len(), 3);
    let source_tombstone: aw_sync_e2ee::SyncOperationV1 = serde_json::from_str(
        &source_operations.iter().find(|record| {
            serde_json::from_str::<aw_sync_e2ee::SyncOperationV1>(&record.operation_json).unwrap().kind
                == aw_models::SyncOperationKindV1::Tombstone
        }).unwrap().operation_json,
    ).unwrap();
    let vault_id = *source.load_sync_key_material().unwrap().unwrap().vault_id();
    let expected_head = SyncManifestHeadV1::new(1, [0x94; 32]);
    source.commit_sync_manifest_head(
        vault_id, 1, source_id, SyncManifestHeadV1::genesis(), expected_head,
    ).unwrap();
    control.invoke(&source, "create_current_sync_snapshot", json!({})).unwrap();
    let snapshot = control.invoke(&source, "export_sync_snapshot", json!({})).unwrap();
    let recovery_kit: aw_models::RecoveryKitV1 = serde_json::from_value(kit["kit"].clone()).unwrap();
    let recovered = open_recovery_kit(&recovery_kit, kit["recovery_phrase"].as_str().unwrap()).unwrap();
    let data_key = unwrap_vault_data_key(&recovered.account_root_key, &recovered.wrapped_vault_key).unwrap();
    let encrypted_snapshot: EncryptedSyncSnapshotV1 = serde_json::from_value(snapshot.clone()).unwrap();
    let plaintext = decrypt_snapshot(&data_key, &encrypted_snapshot).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    let payload_text = String::from_utf8(plaintext.to_vec()).unwrap();
    assert!(!payload_text.contains("private_key") && !payload_text.contains("signing_seed"));
    assert!(payload["sync"]["trusted_devices"][0].get("ed25519_public_key").is_some());
    let args = json!({
        "kit": kit["kit"],
        "recoveryPhrase": kit["recovery_phrase"],
        "snapshot": snapshot,
    });

    assert!(control.invoke(&target, "restore_sync_recovery_kit", args.clone()).is_err());
    assert!(target.load_sync_key_material().unwrap().is_none());
    control.invoke(&target, "restore_sync_recovery_kit", json!({
        "kit": args["kit"],
        "recoveryPhrase": args["recoveryPhrase"],
        "snapshot": args["snapshot"],
        "userAccepted": true,
    })).unwrap();
    assert!(target.load_sync_key_material().unwrap().is_some());
    assert!(target.load_sync_snapshot().unwrap().is_some());
    let restored_identity = target.load_sync_device_identity().unwrap().unwrap();
    assert_ne!(*restored_identity.device_id(), source_id);
    assert_eq!(target.list_sync_operations(source_id, 1, 0, 16).unwrap(), source_operations);
    assert_eq!(target.load_sync_manifest_head(vault_id, 1, source_id).unwrap(), Some(expected_head));
    let expected_signing_key: [u8; 32] = URL_SAFE_NO_PAD.decode(source_identity.public_identity().ed25519_public_key).unwrap().try_into().unwrap();
    assert!(target.list_sync_trusted_devices().unwrap().iter().any(|device| {
        device.device_id == source_id
            && device.ed25519_public_key.as_ref() == Some(&expected_signing_key)
    }));
    assert!(target.sync_baseline_progress().unwrap().unwrap().complete);
    let origin = URL_SAFE_NO_PAD.decode(&source_tombstone.origin_device_id).unwrap().try_into().unwrap();
    let origin_event = source_tombstone.local_event_id.unwrap();
    assert!(target.can_collect_sync_tombstone(origin, origin_event, source_tombstone.counter).unwrap());
    let restored_event = target.get_events("local-a", None, None, None).unwrap().remove(0);
    target.delete_events_by_id("local-a", vec![restored_event.id.unwrap()]).unwrap();
    let local_operations = target.list_sync_operations(*restored_identity.device_id(), 1, 0, 16).unwrap();
    let tombstone: aw_sync_e2ee::SyncOperationV1 = serde_json::from_str(&local_operations[0].operation_json).unwrap();
    assert_eq!(tombstone.kind, aw_models::SyncOperationKindV1::Tombstone);
    assert_eq!(tombstone.origin_device_id, URL_SAFE_NO_PAD.encode(source_id));

    source.close();
    target.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pre_sync_snapshot_preserves_event_identity_without_creating_operations() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-prebaseline-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let source = Datastore::open_encrypted(root.join("source.db").to_string_lossy().into_owned(), "3".repeat(64)).unwrap();
    let target = Datastore::open_encrypted(root.join("target.db").to_string_lossy().into_owned(), "4".repeat(64)).unwrap();
    enable_test_recording(&target);
    target.pause_capture().unwrap();
    let control = SyncControl::new();
    let source_id = [0x65; 16];
    let source_identity = DeviceIdentityV1::from_bytes(
        source_id, Zeroizing::new([0x75; 32]), Zeroizing::new([0x85; 32]),
    );
    source.create_sync_device_identity(&SyncDeviceIdentity::new(
        source_id, source_identity.secret_for_storage(), source_identity.signing_seed_for_storage(),
    )).unwrap();
    create_bucket(&source, "local-prebaseline", "client-a", "event-a");
    let source_event_id = source.get_events("local-prebaseline", None, None, None).unwrap()[0].id.unwrap();
    let kit = control.invoke(&source, "create_sync_recovery_kit", json!({})).unwrap();
    control.invoke(&source, "confirm_sync_recovery_saved", json!({"userConfirmed": true})).unwrap();
    control.invoke(&source, "create_current_sync_snapshot", json!({})).unwrap();
    assert!(source.list_sync_operations(source_id, 1, 0, 8).unwrap().is_empty());
    let snapshot = control.invoke(&source, "export_sync_snapshot", json!({})).unwrap();

    control.invoke(&target, "restore_sync_recovery_kit", json!({
        "kit": kit["kit"],
        "recoveryPhrase": kit["recovery_phrase"],
        "snapshot": snapshot,
        "userAccepted": true,
    })).unwrap();
    let restored_id = *target.load_sync_device_identity().unwrap().unwrap().device_id();
    assert_ne!(restored_id, source_id);
    assert!(target.list_sync_operations(restored_id, 1, 0, 8).unwrap().is_empty());
    finish_baseline(&target);
    let operation: aw_sync_e2ee::SyncOperationV1 = serde_json::from_str(
        &target.list_sync_operations(restored_id, 1, 0, 8).unwrap()[0].operation_json,
    ).unwrap();
    assert_eq!(operation.device_id, URL_SAFE_NO_PAD.encode(restored_id));
    assert_eq!(operation.origin_device_id, URL_SAFE_NO_PAD.encode(source_id));
    assert_eq!(operation.local_event_id, Some(source_event_id as u64));

    source.close();
    target.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rotated_recovery_keeps_counters_but_starts_a_fresh_epoch_stream() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-rotated-recovery-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let source = Datastore::open_encrypted(root.join("source.db").to_string_lossy().into_owned(), "5".repeat(64)).unwrap();
    let target = Datastore::open_encrypted(root.join("target.db").to_string_lossy().into_owned(), "6".repeat(64)).unwrap();
    enable_test_recording(&target);
    target.pause_capture().unwrap();
    let control = SyncControl::new();
    let source_id = [0x66; 16];
    let source_identity = DeviceIdentityV1::from_bytes(
        source_id, Zeroizing::new([0x76; 32]), Zeroizing::new([0x86; 32]),
    );
    source.create_sync_device_identity(&SyncDeviceIdentity::new(
        source_id, source_identity.secret_for_storage(), source_identity.signing_seed_for_storage(),
    )).unwrap();
    create_bucket(&source, "local-rotated", "client-a", "event-a");
    control.invoke(&source, "create_sync_recovery_kit", json!({})).unwrap();
    control.invoke(&source, "confirm_sync_recovery_saved", json!({"userConfirmed": true})).unwrap();
    finish_baseline(&source);
    for _ in 0..4 { source.next_sync_operation_counter(source_id).unwrap(); }
    let vault_id = *source.load_sync_key_material().unwrap().unwrap().vault_id();
    assert_eq!(control.invoke(&source, "rotate_sync_keys", json!({})).unwrap().as_u64(), Some(2));
    let second_kit = control.invoke(&source, "create_sync_recovery_kit", json!({})).unwrap();
    control.invoke(&source, "confirm_sync_recovery_saved", json!({"userConfirmed": true})).unwrap();
    let snapshot = control.invoke(&source, "export_sync_snapshot", json!({})).unwrap();

    control.invoke(&target, "restore_sync_recovery_kit", json!({
        "kit": second_kit["kit"],
        "recoveryPhrase": second_kit["recovery_phrase"],
        "snapshot": snapshot,
        "userAccepted": true,
    })).unwrap();
    let restored_id = *target.load_sync_device_identity().unwrap().unwrap().device_id();
    assert_ne!(restored_id, source_id);
    assert!(target.load_sync_manifest_head(vault_id, 2, source_id).unwrap().is_none());
    assert!(target.sync_baseline_progress().unwrap().is_none());
    let stale_manifest = SyncManifestV1::new_signed(&source_identity, vault_id, 1, 1, [0; 32], Vec::new()).unwrap();
    assert!(target.apply_sync_operations(aw_datastore::SyncApplyBatchV1 { manifest: stale_manifest }).is_err());

    finish_baseline(&target);
    let operations = target.list_sync_operations(restored_id, 2, 0, 8).unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].counter, 6);
    let operation: aw_sync_e2ee::SyncOperationV1 = serde_json::from_str(&operations[0].operation_json).unwrap();
    assert_eq!(operation.origin_device_id, URL_SAFE_NO_PAD.encode(source_id));

    source.close();
    target.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn disabled_sync_keeps_the_encrypted_outbox_and_makes_no_remote_requests() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-disabled-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    finish_baseline(&devices.first);
    let before = devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap();
    assert!(!before.is_empty());

    let remote = CountingSyncStore::new(false);
    assert!(devices.first_control.sync_operations(&devices.first, &remote).is_err());
    assert_eq!(remote.request_count(), 0);
    assert_eq!(devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap(), before);

    devices.first.set_egress_kill_switch(false).unwrap();
    devices.first.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    devices.first.set_egress_kill_switch(true).unwrap();
    assert!(devices.first_control.sync_operations(&devices.first, &remote).is_err());
    assert_eq!(remote.request_count(), 0);
    assert_eq!(devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap(), before);

    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn oversized_operation_pages_are_split_into_signed_manifests() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-large-manifest-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    finish_baseline(&devices.first);
    let events = (0..63).map(|index| Event::new(
        Utc::now() + Duration::seconds(index + 1),
        Duration::seconds(1),
        json!({"app":"client-a","title":format!("{index}-{}", "x".repeat(20_000))})
            .as_object().unwrap().clone(),
    )).collect::<Vec<_>>();
    devices.first.insert_events("local-a", &events).unwrap();
    devices.first.set_egress_kill_switch(false).unwrap();
    devices.first.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    let remote = CountingSyncStore::new(false);

    let result = devices.first_control.sync_operations(&devices.first, &remote).unwrap();

    assert!(result["uploaded_manifests"].as_u64().unwrap() >= 2);
    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn dependent_device_streams_apply_after_their_tombstone_prerequisites() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-cross-stream-dependency-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    finish_baseline(&devices.first);
    finish_baseline(&devices.second);
    for store in [&devices.first, &devices.second] {
        store.set_egress_kill_switch(false).unwrap();
        store.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    }
    let remote = CountingSyncStore::new(false);

    let source_event = devices.second.get_events("local-b", None, None, None).unwrap().remove(0);
    devices.second.delete_events_by_id("local-b", vec![source_event.id.unwrap()]).unwrap();
    devices.second_control.sync_operations(&devices.second, &remote).unwrap();
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();

    let third = Datastore::open_encrypted(root.join("third.db").to_string_lossy().into_owned(), "paired-third-key".repeat(4)).unwrap();
    let third_id = [0x33; 16];
    let third_identity = DeviceIdentityV1::from_bytes(third_id, Zeroizing::new([0x35; 32]), Zeroizing::new([0x45; 32]));
    third.create_sync_device_identity(&SyncDeviceIdentity::new(
        third_id, third_identity.secret_for_storage(), third_identity.signing_seed_for_storage(),
    )).unwrap();
    let material = devices.first.load_sync_key_material().unwrap().unwrap();
    third.install_sync_key_material(&material).unwrap();
    for (peer_id, peer) in [
        (devices.first_id, DeviceIdentityV1::from_bytes(devices.first_id, Zeroizing::new([0x31; 32]), Zeroizing::new([0x41; 32]))),
        (devices.second_id, DeviceIdentityV1::from_bytes(devices.second_id, Zeroizing::new([0x32; 32]), Zeroizing::new([0x42; 32]))),
    ] {
        let public = peer.public_identity();
        third.record_sync_pairing(
            None,
            [peer_id[0].wrapping_add(1); 16],
            peer_id,
            URL_SAFE_NO_PAD.decode(public.x25519_public_key).unwrap().try_into().unwrap(),
            URL_SAFE_NO_PAD.decode(public.ed25519_public_key).unwrap().try_into().unwrap(),
            "2026-09-23T12:00:00Z".into(),
        ).unwrap();
    }
    third.confirm_sync_recovery_saved("2026-09-23T12:00:00Z".into()).unwrap();
    third.begin_sync_baseline().unwrap();
    let third_control = SyncControl::new();
    third_control.invoke(&third, "create_current_sync_snapshot", json!({})).unwrap();
    third.set_egress_kill_switch(false).unwrap();
    third.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();

    let result = third_control.sync_operations(&third, &remote);

    assert!(result.is_ok(), "dependent streams should make progress independent of device-ID order: {result:?}");
    assert!(third.load_sync_manifest_head(devices.vault_id, 1, devices.first_id).unwrap().is_some());
    assert!(third.load_sync_manifest_head(devices.vault_id, 1, devices.second_id).unwrap().is_some());
    third.close();
    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn correction_during_baseline_can_sync_before_its_later_scan_entry() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-baseline-correction-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    let events = (0..64).map(|index| Event::new(
        Utc::now() + Duration::seconds(index + 1),
        Duration::seconds(1),
        json!({"app":"client-a","title":format!("before-{index}")}).as_object().unwrap().clone(),
    )).collect::<Vec<_>>();
    let inserted = devices.first.insert_events("local-a", &events).unwrap();
    devices.first.begin_sync_baseline().unwrap();
    let target_id = inserted.last().unwrap().id.unwrap();
    let mut corrected = devices.first.get_events("local-a", None, None, None).unwrap()
        .into_iter().find(|event| event.id == Some(target_id)).unwrap();
    corrected.data.insert("title".into(), json!("corrected-before-baseline-scan"));
    devices.first.correct_event("local-a", corrected).unwrap();
    finish_baseline(&devices.first);
    finish_baseline(&devices.second);
    for store in [&devices.first, &devices.second] {
        store.set_egress_kill_switch(false).unwrap();
        store.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    }
    let remote = CountingSyncStore::new(false);

    devices.first_control.sync_operations(&devices.first, &remote).unwrap();
    devices.second_control.sync_operations(&devices.second, &remote).unwrap();

    let first_operation: aw_sync_e2ee::SyncOperationV1 = serde_json::from_str(
        &devices.first.list_sync_operations(devices.first_id, 1, 0, 128).unwrap()[0].operation_json,
    ).unwrap();
    assert_eq!(first_operation.kind, aw_models::SyncOperationKindV1::Upsert);
    let remote_bucket = format!("aw-sync-{}", first_operation.sync_bucket_id.unwrap());
    assert!(devices.second.get_events(&remote_bucket, None, None, None).unwrap()
        .iter().any(|event| event.data.get("title") == Some(&json!("corrected-before-baseline-scan"))));

    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn baseline_preparation_is_bounded_local_only_and_keeps_network_consent_off() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-baseline-prepare-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    let more = (0..2).map(|index| Event::new(
        Utc::now() + Duration::seconds(index + 1),
        Duration::seconds(1),
        json!({"app":"client-a","title":format!("more-{index}")}).as_object().unwrap().clone(),
    )).collect::<Vec<_>>();
    devices.first.insert_events("local-a", &more).unwrap();
    let remote = CountingSyncStore::new(false);

    let first = devices.first_control.prepare_sync_baseline(&devices.first, 1).unwrap();
    assert!(!first.complete);
    assert_eq!(remote.request_count(), 0);
    let second = devices.first_control.prepare_sync_baseline(&devices.first, 1).unwrap();
    assert!(!second.complete);
    assert_eq!(remote.request_count(), 0);
    let third = devices.first_control.prepare_sync_baseline(&devices.first, 1).unwrap();
    assert!(third.complete);
    assert_eq!(remote.request_count(), 0);
    assert!(!devices.first.sync_enabled().unwrap());

    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn revoking_the_only_peer_never_calls_the_relay() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-revoked-peer-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    finish_baseline(&devices.first);
    devices.first.set_egress_kill_switch(false).unwrap();
    devices.first.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    let before = devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap();
    devices.first_control.invoke(&devices.first, "revoke_sync_device", json!({
        "deviceId": URL_SAFE_NO_PAD.encode(devices.second_id),
    })).unwrap();
    let remote = CountingSyncStore::new(false);
    assert!(devices.first_control.sync_operations(&devices.first, &remote).is_err());
    assert_eq!(remote.request_count(), 0);
    assert_eq!(devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap(), before);
    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn two_devices_merge_offline_edits_and_tombstones_without_uploading_snapshots() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-operations-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    finish_baseline(&devices.first);
    finish_baseline(&devices.second);
    assert!(!devices.first.load_sync_snapshot().unwrap().unwrap().envelopes.is_empty());
    assert!(!devices.second.load_sync_snapshot().unwrap().unwrap().envelopes.is_empty());
    for store in [&devices.first, &devices.second] {
        store.set_egress_kill_switch(false).unwrap();
        store.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    }
    let remote = CountingSyncStore::new(false);
    let stale = SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([0xEF; 16]),
        vault_id: URL_SAFE_NO_PAD.encode(devices.vault_id),
        key_epoch: 2,
        nonce: URL_SAFE_NO_PAD.encode([0xE1; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([0xE2; 32]),
    };
    remote.put_if_absent(&stale).unwrap();
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();
    devices.second_control.sync_operations(&devices.second, &remote).unwrap();
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();

    let first_op: serde_json::Value = serde_json::from_str(
        &devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap()[0].operation_json,
    ).unwrap();
    let first_bucket_id = first_op["sync_bucket_id"].as_str().unwrap();
    let first_remote_bucket = format!("aw-sync-{first_bucket_id}");
    let second_op: serde_json::Value = serde_json::from_str(
        &devices.second.list_sync_operations(devices.second_id, 1, 0, 16).unwrap()[0].operation_json,
    ).unwrap();
    let second_bucket_id = second_op["sync_bucket_id"].as_str().unwrap();
    let second_remote_bucket = format!("aw-sync-{second_bucket_id}");
    assert_eq!(devices.first.get_events(&second_remote_bucket, None, None, None).unwrap()[0].data["title"], "event-b");
    assert_eq!(devices.second.get_events(&first_remote_bucket, None, None, None).unwrap()[0].data["title"], "event-a");
    assert_eq!(devices.first.load_sync_manifest_head(devices.vault_id, 1, devices.second_id).unwrap().unwrap().revision, 1);
    assert_eq!(devices.second.load_sync_manifest_head(devices.vault_id, 1, devices.first_id).unwrap().unwrap().revision, 1);

    let mut first_event = devices.first.get_events("local-a", None, None, None).unwrap().remove(0);
    first_event.data.insert("title".into(), json!("edit-a"));
    devices.first.correct_event("local-a", first_event).unwrap();
    let mut second_event = devices.second.get_events(&first_remote_bucket, None, None, None).unwrap().remove(0);
    second_event.data.insert("title".into(), json!("edit-b"));
    devices.second.correct_event(&first_remote_bucket, second_event).unwrap();

    devices.second_control.sync_operations(&devices.second, &remote).unwrap();
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();
    devices.second_control.sync_operations(&devices.second, &remote).unwrap();
    let first_winner = devices.first.get_events("local-a", None, None, None).unwrap().remove(0).data["title"].clone();
    let second_winner = devices.second.get_events(&first_remote_bucket, None, None, None).unwrap().remove(0).data["title"].clone();
    assert_eq!(first_winner, json!("edit-b"));
    assert_eq!(second_winner, first_winner);
    let state_before_retry = devices.first.get_events("local-a", None, None, None).unwrap();
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();
    assert_eq!(devices.first.get_events("local-a", None, None, None).unwrap(), state_before_retry);

    let second_event = devices.second.get_events(&first_remote_bucket, None, None, None).unwrap().remove(0);
    devices.second.delete_events_by_id(&first_remote_bucket, vec![second_event.id.unwrap()]).unwrap();
    devices.second_control.sync_operations(&devices.second, &remote).unwrap();
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();
    assert!(devices.first.get_events("local-a", None, None, None).unwrap().is_empty());

    let tombstone = devices.second.list_sync_operations(devices.second_id, 1, 0, 64).unwrap()
        .into_iter()
        .filter_map(|record| serde_json::from_str::<aw_sync_e2ee::SyncOperationV1>(&record.operation_json).ok())
        .find(|operation| operation.kind == aw_models::SyncOperationKindV1::Tombstone)
        .unwrap();
    let origin = URL_SAFE_NO_PAD.decode(&tombstone.origin_device_id).unwrap().try_into().unwrap();
    let origin_event = tombstone.local_event_id.unwrap();
    let tombstone_counter = tombstone.counter;
    devices.first_control.sync_operations(&devices.first, &remote).unwrap();
    devices.second_control.sync_operations(&devices.second, &remote).unwrap();
    let ack_state = devices.second.sync_tombstone_ack_state(origin, origin_event, tombstone_counter).unwrap();
    assert_eq!(ack_state.active_device_ids.len(), 2);
    assert_eq!(ack_state.acknowledged_device_ids.len(), 2);
    assert!(devices.second.can_collect_sync_tombstone(origin, origin_event, tombstone_counter).unwrap());

    let envelopes = remote.list_opaque_heads(&URL_SAFE_NO_PAD.encode(devices.vault_id)).unwrap();
    assert!(envelopes.len() >= 4);
    for envelope in envelopes {
        if envelope.key_epoch == 1 { decrypt_manifest(&devices.data_key, &envelope).unwrap(); }
    }
    assert!(devices.first.get_sync_object(stale.object_id).unwrap().is_none());
    assert!(remote.request_count() > 0);
    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn forged_manifest_from_a_trusted_device_does_not_advance_its_stream() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-forged-manifest-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    finish_baseline(&devices.first);
    devices.first.set_egress_kill_switch(false).unwrap();
    devices.first.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    let remote = CountingSyncStore::new(false);
    let writer = DeviceIdentityV1::from_bytes(
        devices.second_id,
        Zeroizing::new([0x32; 32]),
        Zeroizing::new([0x42; 32]),
    );
    let mut event = Event::new(
        Utc::now(), Duration::seconds(1), json!({"app":"forged"}).as_object().unwrap().clone(),
    );
    event.id = Some(777);
    let operation = create_event_upsert(
        devices.second_id,
        1,
        [0xDD; 16],
        SyncBucketDescriptorV1 { bucket_type: "app".into(), client: "PeakActivity".into(), data: Default::default() },
        &event,
    ).unwrap();
    let mut manifest = SyncManifestV1::new_signed(&writer, devices.vault_id, 1, 1, [0; 32], vec![operation]).unwrap();
    manifest.signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let envelope = encrypt_manifest(&devices.data_key, &SyncChunkHeaderV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([0xDE; 16]),
        vault_id: URL_SAFE_NO_PAD.encode(devices.vault_id),
        key_epoch: 1,
    }, &manifest).unwrap();
    remote.put_if_absent(&envelope).unwrap();

    assert!(devices.first_control.sync_operations(&devices.first, &remote).is_err());
    assert!(devices.first.load_sync_manifest_head(devices.vault_id, 1, devices.second_id).unwrap().is_none());
    assert!(devices.first.list_sync_operations(devices.second_id, 1, 0, 16).unwrap().is_empty());
    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn relay_failure_keeps_local_operations_and_signed_manifest_in_the_outbox() {
    let root = std::env::temp_dir().join(format!(
        "peak-sync-relay-failure-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let devices = paired_devices(&root);
    finish_baseline(&devices.first);
    devices.first.set_egress_kill_switch(false).unwrap();
    devices.first.set_sync_enabled(true, Some("test-sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    let before = devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap();
    let remote = CountingSyncStore::new(true);

    assert!(devices.first_control.sync_operations(&devices.first, &remote).is_err());
    assert!(remote.request_count() > 0);
    assert_eq!(devices.first.list_sync_operations(devices.first_id, 1, 0, 16).unwrap(), before);
    assert_eq!(devices.first.load_sync_manifest_head(devices.vault_id, 1, devices.first_id).unwrap().unwrap().revision, 1);
    let local_objects = devices.first.list_sync_objects(URL_SAFE_NO_PAD.encode(devices.vault_id), None, 64).unwrap().objects;
    assert!(local_objects.iter().any(|envelope| decrypt_manifest(&devices.data_key, envelope).is_ok()));
    devices.first.close();
    devices.second.close();
    fs::remove_dir_all(root).unwrap();
}
