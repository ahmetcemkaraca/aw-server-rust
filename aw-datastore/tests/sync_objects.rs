use aw_datastore::{
    Datastore, SyncHeadCommitV1, SyncKeyMaterial, SyncManifestHeadV1, SyncSnapshotV1,
    SyncTombstoneIdentityV1,
};
use aw_models::SyncEnvelopeV1;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use zeroize::Zeroizing;

fn memory_vault() -> Datastore {
    Datastore::open_encrypted(":memory:".into(), "sync-objects-test-key-".repeat(2)).unwrap()
}

#[test]
fn encrypted_manifest_head_is_monotonic_idempotent_and_persistent() {
    let path = std::env::temp_dir().join(format!(
        "peakactivity-sync-head-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let path_string = path.to_string_lossy().into_owned();
    let encryption_key = "c".repeat(64);
    let store = Datastore::open_encrypted(path_string.clone(), encryption_key.clone()).unwrap();
    let vault_id = [0x31; 16];
    let device_a = [0x21; 16];
    let device_b = [0x22; 16];
    let genesis = SyncManifestHeadV1::genesis();
    let first = SyncManifestHeadV1::new(1, [0x41; 32]);
    let second = SyncManifestHeadV1::new(2, [0x42; 32]);

    assert!(store.load_sync_manifest_head(vault_id, 1, device_a).unwrap().is_none());
    assert_eq!(
        store.commit_sync_manifest_head(vault_id, 1, device_a, genesis, first).unwrap(),
        SyncHeadCommitV1::Advanced
    );
    assert_eq!(
        store.commit_sync_manifest_head(vault_id, 1, device_a, genesis, first).unwrap(),
        SyncHeadCommitV1::Duplicate
    );
    assert!(store
        .commit_sync_manifest_head(vault_id, 1, device_a, genesis, SyncManifestHeadV1::new(1, [0x44; 32]))
        .is_err());
    assert!(store
        .commit_sync_manifest_head(vault_id, 1, device_a, first, SyncManifestHeadV1::new(3, [0x43; 32]))
        .is_err());
    assert!(store
        .commit_sync_manifest_head(vault_id, 1, device_a, SyncManifestHeadV1::new(1, [0x49; 32]), second)
        .is_err());
    assert_eq!(
        store.commit_sync_manifest_head(vault_id, 1, device_a, first, second).unwrap(),
        SyncHeadCommitV1::Advanced
    );
    assert_eq!(
        store.commit_sync_manifest_head(vault_id, 1, device_b, genesis, first).unwrap(),
        SyncHeadCommitV1::Advanced
    );
    store.lock().unwrap();

    let reopened = Datastore::open_encrypted(path_string, encryption_key).unwrap();
    assert_eq!(reopened.load_sync_manifest_head(vault_id, 1, device_a).unwrap(), Some(second));
    assert_eq!(reopened.load_sync_manifest_head(vault_id, 1, device_b).unwrap(), Some(first));
    assert!(reopened.load_sync_manifest_head(vault_id, 2, device_a).unwrap().is_none());
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn per_device_operation_counters_are_monotonic_and_persistent() {
    let path = std::env::temp_dir().join(format!(
        "peakactivity-sync-counter-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let path_string = path.to_string_lossy().into_owned();
    let encryption_key = "d".repeat(64);
    let device_id = [0x51; 16];
    let store = Datastore::open_encrypted(path_string.clone(), encryption_key.clone()).unwrap();
    assert_eq!(store.next_sync_operation_counter(device_id).unwrap(), 1);
    assert_eq!(store.next_sync_operation_counter(device_id).unwrap(), 2);
    store.lock().unwrap();

    let reopened = Datastore::open_encrypted(path_string, encryption_key).unwrap();
    assert_eq!(reopened.next_sync_operation_counter(device_id).unwrap(), 3);
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn tombstone_collection_waits_for_active_device_acknowledgements() {
    let store = memory_vault();
    let event_origin = [0x21; 16];
    let first_device = [0x31; 16];
    let second_device = [0x32; 16];
    let at = "2026-09-23T12:00:00Z".to_owned();
    assert!(store.can_collect_sync_tombstone(event_origin, 0, 0).is_err());
    store.record_sync_pairing(
        Some(SyncKeyMaterial::new(Zeroizing::new([0x61; 32]), [0x62; 16], 1, [0x63; 24], [0x64; 48])),
        [0x41; 16], first_device, [0x51; 32], [0x61; 32], at.clone(),
    ).unwrap();
    store.record_sync_pairing(None, [0x42; 16], second_device, [0x52; 32], [0x62; 32], at.clone()).unwrap();

    store.acknowledge_sync_tombstone(event_origin, 42, 8, first_device, at.clone()).unwrap();
    assert!(!store.can_collect_sync_tombstone(event_origin, 42, 8).unwrap());
    store.acknowledge_sync_tombstone(event_origin, 42, 8, second_device, at.clone()).unwrap();
    assert!(store.can_collect_sync_tombstone(event_origin, 42, 8).unwrap());

    let snapshot = SyncSnapshotV1::new([0x70; 16], vec![SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([0x71; 16]),
        vault_id: URL_SAFE_NO_PAD.encode([0x62; 16]),
        key_epoch: 2,
        nonce: URL_SAFE_NO_PAD.encode([0x72; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([0x73; 16]),
    }]);
    assert!(store.rotate_sync_key_material(
        SyncKeyMaterial::new(Zeroizing::new([0x65; 32]), [0x62; 16], 2, [0x66; 24], [0x67; 48]),
        snapshot, Some(second_device), at.clone(),
    ).unwrap());
    assert!(store.can_collect_sync_tombstone(event_origin, 42, 8).unwrap());
    assert!(store.acknowledge_sync_tombstone(event_origin, 42, 8, first_device, at.clone()).is_err());
    store.record_sync_pairing(
        None, [0x74; 16], first_device, [0x51; 32], [0x61; 32], "2026-09-23T12:11:00Z".into(),
    ).unwrap();
    assert!(!store.can_collect_sync_tombstone(event_origin, 42, 8).unwrap());
    store.acknowledge_sync_tombstone(event_origin, 42, 8, first_device, at.clone()).unwrap();
    assert!(store.can_collect_sync_tombstone(event_origin, 42, 8).unwrap());
    assert!(store
        .record_sync_pairing(None, [0x43; 16], second_device, [0x52; 32], [0x62; 32], "2026-09-23T12:10:00Z".into())
        .is_err());
    assert!(store.can_collect_sync_tombstone(event_origin, 42, 8).unwrap());
    store.close();
}

#[test]
fn ciphertext_object_store_is_immutable_and_deletion_requires_active_acknowledgements() {
    let store = memory_vault();
    let vault_id = [0x81; 16];
    let device_id = [0x82; 16];
    let at = "2026-09-23T12:30:00Z".to_owned();
    store.record_sync_pairing(
        Some(SyncKeyMaterial::new(Zeroizing::new([0x83; 32]), vault_id, 1, [0x84; 24], [0x85; 48])),
        [0x86; 16], device_id, [0x87; 32], [0x88; 32], at.clone(),
    ).unwrap();
    let envelope = SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([0x88; 16]),
        vault_id: URL_SAFE_NO_PAD.encode(vault_id),
        key_epoch: 1,
        nonce: URL_SAFE_NO_PAD.encode([0x89; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([0x8A; 32]),
    };
    assert!(store.put_sync_object(envelope.clone(), at.clone()).unwrap());
    assert!(!store.put_sync_object(envelope.clone(), at.clone()).unwrap());
    assert_eq!(store.get_sync_object(envelope.object_id.clone()).unwrap(), Some(envelope.clone()));
    let page = store.list_sync_objects(envelope.vault_id.clone(), None, 10).unwrap();
    assert_eq!(page.objects, vec![envelope.clone()]);
    assert!(page.next_cursor.is_none());

    let mut conflicting = envelope.clone();
    conflicting.ciphertext = URL_SAFE_NO_PAD.encode([0x8B; 32]);
    assert!(store.put_sync_object(conflicting, at.clone()).is_err());

    let tombstone = SyncTombstoneIdentityV1 {
        origin_device_id: [0x91; 16],
        local_event_id: 7,
        tombstone_counter: 4,
    };
    assert!(store.delete_sync_object_after_tombstones(
        envelope.object_id.clone(), vec![tombstone.clone()], at.clone(),
    ).is_err());
    store.acknowledge_sync_tombstone(
        tombstone.origin_device_id, tombstone.local_event_id, tombstone.tombstone_counter,
        device_id, at.clone(),
    ).unwrap();
    assert!(store.delete_sync_object_after_tombstones(
        envelope.object_id.clone(), vec![tombstone], at,
    ).unwrap());
    assert!(store.get_sync_object(envelope.object_id).unwrap().is_none());
    let history = store.list_sync_object_history(10).unwrap();
    assert_eq!(history.iter().map(|event| event.action.as_str()).collect::<Vec<_>>(), vec!["deleted", "stored"]);
    store.close();
}

#[test]
fn opaque_object_listing_pages_by_object_id_without_skipping_objects() {
    let store = memory_vault();
    let vault_id = URL_SAFE_NO_PAD.encode([0xA1; 16]);
    for id in 1..=3u8 {
        store.put_sync_object(SyncEnvelopeV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode([id; 16]),
            vault_id: vault_id.clone(),
            key_epoch: 1,
            nonce: URL_SAFE_NO_PAD.encode([id.wrapping_add(4); 24]),
            ciphertext: URL_SAFE_NO_PAD.encode([id.wrapping_add(8); 16]),
        }, "2026-09-23T12:30:00Z".into()).unwrap();
    }

    let first = store.list_sync_objects(vault_id.clone(), None, 1).unwrap();
    let next = first.next_cursor.clone().unwrap();
    let second = store.list_sync_objects(vault_id.clone(), Some(next), 1).unwrap();
    let third = store.list_sync_objects(vault_id, second.next_cursor.clone(), 1).unwrap();
    assert_eq!(first.objects.len(), 1);
    assert_eq!(second.objects.len(), 1);
    assert_eq!(third.objects.len(), 1);
    assert!(third.next_cursor.is_none());
    assert_ne!(first.objects[0].object_id, second.objects[0].object_id);
    assert_ne!(second.objects[0].object_id, third.objects[0].object_id);
    store.close();
}
