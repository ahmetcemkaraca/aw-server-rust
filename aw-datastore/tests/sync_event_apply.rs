use aw_datastore::{
    Datastore, SyncApplyBatchV1, SyncDeviceIdentity, SyncHeadCommitV1, SyncKeyMaterial,
    SyncManifestHeadV1, SyncSnapshotV1, SyncStoredOperationV1,
};
use aw_models::{Bucket, BucketMetadata, Event, SyncBucketDescriptorV1, SyncEnvelopeV1, TryVec};
use aw_sync_e2ee::{
    create_event_correction, create_event_tombstone, create_event_upsert, DeviceIdentityV1,
    SyncManifestV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use ring::digest::{digest, SHA256};
use serde_json::json;
use zeroize::Zeroizing;

fn database_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "peakactivity-{name}-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ))
}

fn operation(device_id: [u8; 16], counter: u64, epoch: u64, json: &str) -> SyncStoredOperationV1 {
    let hash = digest(&SHA256, json.as_bytes());
    let content_hash: [u8; 32] = hash.as_ref().try_into().unwrap();
    SyncStoredOperationV1 {
        device_id,
        counter,
        key_epoch: epoch,
        operation_json: json.to_owned(),
        content_hash,
    }
}

fn manifest_head_hash(manifest: &SyncManifestV1) -> [u8; 32] {
    URL_SAFE_NO_PAD.decode(&manifest.head_hash).unwrap().try_into().unwrap()
}

fn event(label: &str) -> Event {
    Event::new(
        Utc::now(),
        Duration::seconds(1),
        json!({"app": label}).as_object().unwrap().clone(),
    )
}

fn sync_store(name: &str) -> (Datastore, std::path::PathBuf, String, [u8; 16]) {
    let path = database_path(name);
    let key = "sync-event-apply-key-".repeat(3);
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
    let device_id = [0xA1; 16];
    store.create_sync_device_identity(&SyncDeviceIdentity::new(
        device_id,
        Zeroizing::new([0xA2; 32]),
        Zeroizing::new([0xA3; 32]),
    )).unwrap();
    store.install_sync_key_material(&SyncKeyMaterial::new(
        Zeroizing::new([0xA4; 32]), [0xA5; 16], 1, [0xA6; 24], [0xA7; 48],
    )).unwrap();
    store.create_bucket(&Bucket {
        bid: None,
        id: "local-sync-bucket".into(),
        _type: "app".into(),
        client: "PeakActivity".into(),
        hostname: "host".into(),
        created: None,
        data: Default::default(),
        metadata: BucketMetadata::default(),
        events: Some(TryVec::new(Vec::new())),
        last_updated: None,
    }).unwrap();
    (store, path, key, device_id)
}

fn remote_signer(store: &Datastore, peer_id: [u8; 16]) -> DeviceIdentityV1 {
    let signer = DeviceIdentityV1::from_bytes(
        peer_id,
        Zeroizing::new([0xB2; 32]),
        Zeroizing::new([0xB3; 32]),
    );
    let public = signer.public_identity();
    let exchange_key: [u8; 32] = URL_SAFE_NO_PAD.decode(public.x25519_public_key).unwrap().try_into().unwrap();
    let signing_key: [u8; 32] = URL_SAFE_NO_PAD.decode(public.ed25519_public_key).unwrap().try_into().unwrap();
    store.record_sync_pairing(
        None,
        [peer_id[0].wrapping_add(3); 16],
        peer_id,
        exchange_key,
        signing_key,
        "2026-09-23T12:00:00Z".into(),
    ).unwrap();
    signer
}

fn remote_event() -> Event {
    let mut event = event("remote-app");
    event.id = Some(42);
    event.data.insert("title".into(), json!("original title"));
    event
}

fn bucket_descriptor() -> SyncBucketDescriptorV1 {
    SyncBucketDescriptorV1 {
        bucket_type: "app".into(),
        client: "PeakActivity".into(),
        data: Default::default(),
    }
}

fn apply_batch(manifest: SyncManifestV1) -> SyncApplyBatchV1 {
    SyncApplyBatchV1 { manifest }
}

#[test]
fn per_device_stream_heads_are_independent_by_device_and_epoch() {
    let path = database_path("sync-stream-heads");
    let encryption_key = "c".repeat(64);
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), encryption_key.clone()).unwrap();
    let vault_id = [0x31; 16];
    let device_a = [0x41; 16];
    let device_b = [0x51; 16];
    let genesis = SyncManifestHeadV1::genesis();
    let head_a = SyncManifestHeadV1::new(1, [0x61; 32]);
    let head_b = SyncManifestHeadV1::new(1, [0x71; 32]);

    assert_eq!(store.commit_sync_manifest_head(vault_id, 1, device_a, genesis, head_a).unwrap(), SyncHeadCommitV1::Advanced);
    assert_eq!(store.commit_sync_manifest_head(vault_id, 1, device_b, genesis, head_b).unwrap(), SyncHeadCommitV1::Advanced);
    assert_eq!(store.load_sync_manifest_head(vault_id, 1, device_a).unwrap(), Some(head_a));
    assert_eq!(store.load_sync_manifest_head(vault_id, 1, device_b).unwrap(), Some(head_b));
    assert!(store.load_sync_manifest_head(vault_id, 2, device_a).unwrap().is_none());
    store.lock().unwrap();

    let reopened = Datastore::open_encrypted(path.to_string_lossy().into_owned(), encryption_key).unwrap();
    assert_eq!(reopened.load_sync_manifest_head(vault_id, 1, device_a).unwrap(), Some(head_a));
    assert_eq!(reopened.load_sync_manifest_head(vault_id, 1, device_b).unwrap(), Some(head_b));
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn operation_records_are_idempotent_and_reject_counter_forks() {
    let path = database_path("sync-operation-records");
    let encryption_key = "d".repeat(64);
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), encryption_key.clone()).unwrap();
    let device = [0x21; 16];
    let original = operation(device, 1, 1, r#"{"kind":"upsert","app":"Editor"}"#);

    assert!(store.put_sync_operation(original.clone()).unwrap());
    assert!(!store.put_sync_operation(original.clone()).unwrap());
    assert!(store.put_sync_operation(operation(device, 1, 1, r#"{"kind":"upsert","app":"Other"}"#)).is_err());
    store.lock().unwrap();

    let reopened = Datastore::open_encrypted(path.to_string_lossy().into_owned(), encryption_key).unwrap();
    assert_eq!(reopened.list_sync_operations(device, 1, 0, 16).unwrap(), vec![original]);
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn sync_device_signing_seed_is_encrypted_and_persisted() {
    let path = database_path("sync-device-signing-seed");
    let encryption_key = "e".repeat(64);
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), encryption_key.clone()).unwrap();
    let device_id = [0x31; 16];
    let x25519_seed = Zeroizing::new([0x41; 32]);
    let signing_seed = Zeroizing::new([0x51; 32]);
    let identity = SyncDeviceIdentity::new(device_id, x25519_seed.clone(), signing_seed.clone());
    store.create_sync_device_identity(&identity).unwrap();
    store.lock().unwrap();

    let reopened = Datastore::open_encrypted(path.to_string_lossy().into_owned(), encryption_key).unwrap();
    let restored = reopened.load_sync_device_identity().unwrap().unwrap();
    assert_eq!(restored.device_id(), &device_id);
    assert_eq!(&*restored.private_key(), &*x25519_seed);
    assert_eq!(&*restored.signing_seed(), &*signing_seed);
    assert!(!format!("{restored:?}").contains("81"));
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn sync_identity_cannot_be_read_or_written_in_a_plaintext_datastore() {
    let store = Datastore::new_in_memory(false);
    assert!(store.load_sync_device_identity().is_err());
    let identity = SyncDeviceIdentity::new(
        [0x61; 16],
        Zeroizing::new([0x62; 32]),
        Zeroizing::new([0x63; 32]),
    );
    assert!(store.create_sync_device_identity(&identity).is_err());
}

#[test]
fn baseline_resumes_and_journals_post_watermark_inserts_once() {
    let (store, path, key, device_id) = sync_store("sync-baseline-resume");
    let bucket_id = "local-sync-bucket";
    let original = store.insert_events(bucket_id, &[event("before-a"), event("before-b")]).unwrap();
    assert_eq!(store.list_sync_operations(device_id, 1, 0, 16).unwrap().len(), 0);

    let started = store.begin_sync_baseline().unwrap();
    assert_eq!(started.baseline_max_event_id, original[1].id.unwrap() as u64);
    let first = store.process_sync_baseline_batch(1).unwrap();
    assert!(!first.complete);
    store.lock().unwrap();

    let resumed = Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
    let new_event = resumed.insert_events(bucket_id, &[event("after-watermark")]).unwrap();
    assert!(new_event[0].id.unwrap() as u64 > started.baseline_max_event_id);
    while !resumed.process_sync_baseline_batch(1).unwrap().complete {}

    let operations = resumed.list_sync_operations(device_id, 1, 0, 16).unwrap();
    assert_eq!(operations.len(), 3);
    let mut event_ids = operations.iter().map(|stored| {
        serde_json::from_str::<serde_json::Value>(&stored.operation_json).unwrap()["local_event_id"]
            .as_u64().unwrap()
    }).collect::<Vec<_>>();
    event_ids.sort_unstable();
    assert_eq!(event_ids, original.iter().chain(&new_event).map(|e| e.id.unwrap() as u64).collect::<Vec<_>>());
    resumed.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn correction_of_an_unscanned_baseline_event_journals_full_state_first() {
    let (store, path, _, device_id) = sync_store("sync-baseline-correction");
    let bucket_id = "local-sync-bucket";
    let events = (0..65).map(|index| event(&format!("before-{index}"))).collect::<Vec<_>>();
    let inserted = store.insert_events(bucket_id, &events).unwrap();
    store.begin_sync_baseline().unwrap();

    let last_id = inserted.last().unwrap().id.unwrap();
    let mut corrected = store.get_events(bucket_id, None, None, None).unwrap()
        .into_iter().find(|candidate| candidate.id == Some(last_id)).unwrap();
    corrected.data.insert("app".into(), serde_json::json!("corrected-before-scan"));
    store.correct_event(bucket_id, corrected).unwrap();

    let operations = store.list_sync_operations(device_id, 1, 0, 8).unwrap();
    let operation: aw_sync_e2ee::SyncOperationV1 = serde_json::from_str(&operations[0].operation_json).unwrap();
    assert_eq!(operation.kind, aw_models::SyncOperationKindV1::Upsert);
    assert!(operation.fields.contains_key("timestamp"));
    assert!(operation.fields.contains_key("duration_ns"));
    assert_eq!(operation.fields["data:app"], serde_json::json!("corrected-before-scan"));

    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn local_event_and_outbox_insert_roll_back_together() {
    let (store, path, key, device_id) = sync_store("sync-local-atomic");
    store.begin_sync_baseline().unwrap();
    store.lock().unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "key", key.as_str()).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_sync_operation BEFORE INSERT ON sync_operations BEGIN SELECT RAISE(ABORT, 'injected sync write failure'); END;").unwrap();
    drop(conn);

    let reopened = Datastore::open_encrypted(path.to_string_lossy().into_owned(), key).unwrap();
    assert!(reopened.insert_events("local-sync-bucket", &[event("must-rollback")]).is_err());
    assert!(reopened.get_events("local-sync-bucket", None, None, None).unwrap().is_empty());
    assert!(reopened.list_sync_operations(device_id, 1, 0, 16).unwrap().is_empty());
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn key_rotation_starts_a_fresh_baseline_without_resetting_device_counters() {
    let (store, path, _, device_id) = sync_store("sync-baseline-rotation");
    store.insert_events("local-sync-bucket", &[event("before-rotation")]).unwrap();
    let first = store.begin_sync_baseline().unwrap();
    assert!(!first.complete);
    while !store.process_sync_baseline_batch(8).unwrap().complete {}
    assert_eq!(store.list_sync_operations(device_id, 1, 0, 8).unwrap()[0].counter, 1);

    let snapshot = SyncSnapshotV1::new([0xC8; 16], vec![SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([0xC9; 16]),
        vault_id: URL_SAFE_NO_PAD.encode([0xA5; 16]),
        key_epoch: 2,
        nonce: URL_SAFE_NO_PAD.encode([0xCA; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([0xCB; 32]),
    }]);
    store.rotate_sync_key_material(
        SyncKeyMaterial::new(Zeroizing::new([0xD1; 32]), [0xA5; 16], 2, [0xD2; 24], [0xD3; 48]),
        snapshot,
        None,
        "2026-09-23T12:01:00Z".into(),
    ).unwrap();
    assert!(!store.sync_enabled().unwrap());

    let restarted = store.begin_sync_baseline().unwrap();
    assert!(!restarted.complete);
    assert_eq!(restarted.baseline_max_event_id, first.baseline_max_event_id);
    assert!(store.process_sync_baseline_batch(8).unwrap().complete);
    assert_eq!(store.list_sync_operations(device_id, 2, 0, 8).unwrap()[0].counter, 2);
    assert_eq!(store.list_sync_operations(device_id, 1, 0, 8).unwrap()[0].counter, 1);
    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn delete_import_retention_and_bucket_delete_append_tombstones() {
    let (store, path, _, device_id) = sync_store("sync-local-tombstones");
    let bucket_id = "local-sync-bucket";
    store.begin_sync_baseline().unwrap();

    let direct = store.insert_events(bucket_id, &[event("delete-by-id")]).unwrap();
    store.delete_events_by_id(bucket_id, vec![direct[0].id.unwrap()]).unwrap();

    let now = Utc::now();
    let old = Event::new(now - Duration::days(10), Duration::seconds(1), json!({"app":"retention"}).as_object().unwrap().clone());
    store.import_events(bucket_id, &[old]).unwrap();
    assert_eq!(store.apply_raw_retention(1, now).unwrap(), 1);

    let range = Event::new(now, Duration::seconds(1), json!({"app":"range"}).as_object().unwrap().clone());
    store.import_events(bucket_id, &[range]).unwrap();
    store.delete_events_in_range(
        bucket_id,
        now - Duration::seconds(1),
        now + Duration::seconds(2),
    ).unwrap();

    store.insert_events(bucket_id, &[event("delete-bucket")]).unwrap();
    store.delete_bucket(bucket_id).unwrap();

    let operations = store.list_sync_operations(device_id, 1, 0, 32).unwrap();
    let tombstone_count = operations.iter().filter(|operation| {
        serde_json::from_str::<serde_json::Value>(&operation.operation_json).unwrap()["kind"] == "tombstone"
    }).count();
    assert_eq!(tombstone_count, 4);
    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn remote_correction_updates_its_mapped_event_and_duplicate_apply_is_idempotent() {
    let (store, path, _, _) = sync_store("sync-remote-correction");
    let peer_id = [0xB1; 16];
    let signer = remote_signer(&store, peer_id);
    let vault_id = [0xA5; 16];
    let sync_bucket_id = [0xC1; 16];
    let upsert = create_event_upsert(peer_id, 1, sync_bucket_id, bucket_descriptor(), &remote_event()).unwrap();
    let first = SyncManifestV1::new_signed(&signer, vault_id, 1, 1, [0; 32], vec![upsert.clone()]).unwrap();
    let first_batch = apply_batch(first.clone());
    assert_eq!(store.apply_sync_operations(first_batch.clone()).unwrap(), SyncHeadCommitV1::Advanced);
    let local_bucket = format!("aw-sync-{}", URL_SAFE_NO_PAD.encode(sync_bucket_id));
    let before = store.get_events(&local_bucket, None, None, None).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].data["title"], json!("original title"));
    assert_eq!(store.apply_sync_operations(first_batch).unwrap(), SyncHeadCommitV1::Duplicate);
    assert_eq!(store.get_events(&local_bucket, None, None, None).unwrap(), before);

    let correction = create_event_correction(
        peer_id, 2, peer_id, 42, sync_bucket_id,
        std::collections::BTreeMap::from([("data:title".into(), json!("corrected title"))]),
    ).unwrap();
    let second = SyncManifestV1::new_signed(&signer, vault_id, 1, 2, manifest_head_hash(&first), vec![correction]).unwrap();
    let second_batch = apply_batch(second.clone());
    assert_eq!(store.apply_sync_operations(second_batch).unwrap(), SyncHeadCommitV1::Advanced);
    assert_eq!(store.get_events(&local_bucket, None, None, None).unwrap()[0].data["title"], json!("corrected title"));
    assert_eq!(store.next_sync_operation_counter([0xA1; 16]).unwrap(), 3);
    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn remote_stream_rejects_a_new_operation_below_its_observed_counter() {
    let (store, path, _, _) = sync_store("sync-counter-rollback");
    let peer_id = [0xB1; 16];
    let signer = remote_signer(&store, peer_id);
    let vault_id = [0xA5; 16];
    let sync_bucket_id = [0xC6; 16];
    let upsert = create_event_upsert(peer_id, 1, sync_bucket_id, bucket_descriptor(), &remote_event()).unwrap();
    let first = SyncManifestV1::new_signed(&signer, vault_id, 1, 1, [0; 32], vec![upsert]).unwrap();
    store.apply_sync_operations(apply_batch(first.clone())).unwrap();
    let high = create_event_correction(
        peer_id, 3, peer_id, 42, sync_bucket_id,
        std::collections::BTreeMap::from([("data:title".into(), json!("counter-three"))]),
    ).unwrap();
    let second = SyncManifestV1::new_signed(&signer, vault_id, 1, 2, manifest_head_hash(&first), vec![high]).unwrap();
    store.apply_sync_operations(apply_batch(second.clone())).unwrap();
    let lower = create_event_correction(
        peer_id, 2, peer_id, 42, sync_bucket_id,
        std::collections::BTreeMap::from([("data:title".into(), json!("counter-two"))]),
    ).unwrap();
    let third = SyncManifestV1::new_signed(&signer, vault_id, 1, 3, manifest_head_hash(&second), vec![lower]).unwrap();
    assert!(store.apply_sync_operations(apply_batch(third)).is_err());
    let local_bucket = format!("aw-sync-{}", URL_SAFE_NO_PAD.encode(sync_bucket_id));
    assert_eq!(store.get_events(&local_bucket, None, None, None).unwrap()[0].data["title"], json!("counter-three"));
    assert_eq!(store.load_sync_manifest_head(vault_id, 1, peer_id).unwrap().unwrap().revision, 2);
    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn remote_event_cannot_move_between_sync_buckets() {
    let (store, path, _, _) = sync_store("sync-remote-bucket-fork");
    let peer_id = [0xB1; 16];
    let signer = remote_signer(&store, peer_id);
    let vault_id = [0xA5; 16];
    let first_bucket = [0xC4; 16];
    let second_bucket = [0xC5; 16];
    let upsert = create_event_upsert(peer_id, 1, first_bucket, bucket_descriptor(), &remote_event()).unwrap();
    let first = SyncManifestV1::new_signed(&signer, vault_id, 1, 1, [0; 32], vec![upsert.clone()]).unwrap();
    store.apply_sync_operations(apply_batch(first.clone())).unwrap();

    let correction = create_event_correction(
        peer_id, 2, peer_id, 42, second_bucket,
        std::collections::BTreeMap::from([("data:title".into(), json!("moved"))]),
    ).unwrap();
    let second = SyncManifestV1::new_signed(&signer, vault_id, 1, 2, manifest_head_hash(&first), vec![correction]).unwrap();
    assert!(store.apply_sync_operations(apply_batch(second)).is_err());
    assert_eq!(store.list_sync_operations(peer_id, 1, 0, 16).unwrap().len(), 1);
    assert_eq!(store.load_sync_manifest_head(vault_id, 1, peer_id).unwrap().unwrap().revision, 1);
    let local_bucket = format!("aw-sync-{}", URL_SAFE_NO_PAD.encode(first_bucket));
    assert_eq!(store.get_events(&local_bucket, None, None, None).unwrap()[0].data["title"], json!("original title"));
    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn remote_tombstone_keeps_a_mapping_that_prevents_stale_resurrection() {
    let (store, path, key, _) = sync_store("sync-remote-tombstone");
    let origin_device = [0xB1; 16];
    let deleting_device = [0xB8; 16];
    let origin_signer = remote_signer(&store, origin_device);
    let deleting_signer = remote_signer(&store, deleting_device);
    let vault_id = [0xA5; 16];
    let sync_bucket_id = [0xC2; 16];
    let tombstone = create_event_tombstone(deleting_device, 2, origin_device, 42, sync_bucket_id).unwrap();
    let first = SyncManifestV1::new_signed(&deleting_signer, vault_id, 1, 1, [0; 32], vec![tombstone.clone()]).unwrap();
    store.apply_sync_operations(apply_batch(first)).unwrap();

    let local_bucket = format!("aw-sync-{}", URL_SAFE_NO_PAD.encode(sync_bucket_id));
    assert!(store.get_bucket(&local_bucket).is_err());
    store.lock().unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "key", key.as_str()).unwrap();
    let (mapped_bucket, local_event_id, deleted): (String, Option<i64>, bool) = conn.query_row(
        "SELECT local_bucket_id,local_event_id,deleted FROM sync_event_mappings WHERE origin_device_id = ?1 AND origin_event_id = 42",
        [&origin_device[..]],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(mapped_bucket, local_bucket);
    assert!(local_event_id.is_none());
    assert!(deleted);
    drop(conn);
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), key).unwrap();

    let upsert = create_event_upsert(origin_device, 1, sync_bucket_id, bucket_descriptor(), &remote_event()).unwrap();
    let second = SyncManifestV1::new_signed(&origin_signer, vault_id, 1, 1, [0; 32], vec![upsert.clone()]).unwrap();
    store.apply_sync_operations(apply_batch(second.clone())).unwrap();
    assert!(store.get_bucket(&local_bucket).is_err());

    let resurrected = create_event_upsert(origin_device, 3, sync_bucket_id, bucket_descriptor(), &remote_event()).unwrap();
    let third = SyncManifestV1::new_signed(&origin_signer, vault_id, 1, 2, manifest_head_hash(&second), vec![resurrected]).unwrap();
    store.apply_sync_operations(apply_batch(third)).unwrap();
    assert_eq!(store.get_events(&local_bucket, None, None, None).unwrap().len(), 1);
    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn failed_stream_checkpoint_rolls_back_remote_events_mappings_and_operations() {
    let (store, path, key, _) = sync_store("sync-remote-atomic");
    let peer_id = [0xB1; 16];
    let signer = remote_signer(&store, peer_id);
    let vault_id = [0xA5; 16];
    let sync_bucket_id = [0xC3; 16];
    let upsert = create_event_upsert(peer_id, 1, sync_bucket_id, bucket_descriptor(), &remote_event()).unwrap();
    let manifest = SyncManifestV1::new_signed(&signer, vault_id, 1, 1, [0; 32], vec![upsert]).unwrap();
    let batch = apply_batch(manifest);
    store.lock().unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "key", key.as_str()).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_sync_head BEFORE INSERT ON sync_stream_heads BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END;").unwrap();
    drop(conn);

    let reopened = Datastore::open_encrypted(path.to_string_lossy().into_owned(), key).unwrap();
    assert!(reopened.apply_sync_operations(batch).is_err());
    let local_bucket = format!("aw-sync-{}", URL_SAFE_NO_PAD.encode(sync_bucket_id));
    assert!(reopened.get_bucket(&local_bucket).is_err());
    assert!(reopened.list_sync_operations(peer_id, 1, 0, 16).unwrap().is_empty());
    assert!(reopened.load_sync_manifest_head(vault_id, 1, peer_id).unwrap().is_none());
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}
