use aw_datastore::{Datastore, SyncDeviceIdentity, SyncHeadCommitV1, SyncKeyMaterial, SyncManifestHeadV1, SyncSnapshotV1};
use aw_models::{Bucket, BucketMetadata, BucketsExport, Event, SyncEnvelopeV1, TryVec};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use zeroize::Zeroizing;

fn memory_vault() -> Datastore {
    Datastore::open_encrypted(":memory:".into(), "sync-identity-test-key-".repeat(2)).unwrap()
}

fn snapshot(epoch: u64, vault_id: [u8; 16], id: u8) -> SyncSnapshotV1 {
    SyncSnapshotV1::new([id; 16], vec![SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([id.wrapping_add(1); 16]),
        vault_id: URL_SAFE_NO_PAD.encode(vault_id),
        key_epoch: epoch,
        nonce: URL_SAFE_NO_PAD.encode([id.wrapping_add(2); 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([id.wrapping_add(3); 16]),
    }])
}

#[test]
fn sync_device_identity_is_persisted_once_and_survives_reopen() {
    let path = std::env::temp_dir().join(format!(
        "peakactivity-sync-identity-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let path_string = path.to_string_lossy().into_owned();
    let encryption_key = "a".repeat(64);
    let store = Datastore::open_encrypted(path_string.clone(), encryption_key.clone()).unwrap();
    assert!(store.load_sync_device_identity().unwrap().is_none());

    let device_id = [0x41; 16];
    let private_key = Zeroizing::new([0xA7; 32]);
    let signing_seed = Zeroizing::new([0xB7; 32]);
    let identity = SyncDeviceIdentity::new(device_id, private_key.clone(), signing_seed.clone());
    store.create_sync_device_identity(&identity).unwrap();
    assert!(store.create_sync_device_identity(&identity).is_err());
    let key_material = SyncKeyMaterial::new(
        Zeroizing::new([0xC3; 32]),
        [0xD4; 16],
        2,
        [0xE5; 24],
        [0xF6; 48],
    );
    let peer_id = [0x58; 16];
    let peer_key = [0x69; 32];
    let peer_signing_key = [0x6A; 32];
    let offer_id = [0x47; 16];
    let paired_at = "2026-09-23T12:00:00Z".to_owned();
    store
        .record_sync_pairing(Some(key_material.clone()), offer_id, peer_id, peer_key, peer_signing_key, paired_at.clone())
        .unwrap();
    assert!(store.sync_recovery_confirmation().unwrap().is_none());
    store.confirm_sync_recovery_saved(paired_at.clone()).unwrap();
    assert!(store
        .record_sync_pairing(
            None,
            offer_id,
            [0x79; 16],
            [0x7A; 32],
            [0x7B; 32],
            "2026-09-23T12:01:00Z".into(),
        )
        .is_err());
    assert!(store
        .record_sync_pairing(
            Some(SyncKeyMaterial::new(
                Zeroizing::new([0xC3; 32]), [0xD4; 16], 2, [0xE7; 24], [0xF8; 48],
            )),
            [0x48; 16],
            [0x79; 16],
            [0x7A; 32],
            [0x7B; 32],
            "2026-09-23T12:01:00Z".into(),
        )
        .is_err());
    assert_eq!(store.list_sync_trusted_devices().unwrap()[0].paired_at, paired_at);
    assert_eq!(store.list_sync_device_access_history(10).unwrap()[0].action, "paired");
    store.lock().unwrap();

    assert!(Datastore::open_encrypted(path_string.clone(), "b".repeat(64)).is_err());
    let reopened = Datastore::open_encrypted(path_string, encryption_key).unwrap();
    let restored = reopened.load_sync_device_identity().unwrap().unwrap();
    assert_eq!(restored.device_id(), &device_id);
    assert!(&*restored.private_key() == &*private_key);
    assert!(&*restored.signing_seed() == &*signing_seed);
    assert!(!format!("{restored:?}").contains("167"));
    assert!(!format!("{restored:?}").contains("183"));
    assert!(reopened.get_key_values("settings.sync.%").unwrap().is_empty());
    let restored_keys = reopened.load_sync_key_material().unwrap().unwrap();
    assert!(&*restored_keys.account_root_key() == &[0xC3; 32]);
    assert_eq!(restored_keys.vault_id(), &[0xD4; 16]);
    assert_eq!(restored_keys.key_epoch(), 2);
    assert_eq!(restored_keys.wrapped_nonce(), &[0xE5; 24]);
    assert_eq!(restored_keys.wrapped_ciphertext(), &[0xF6; 48]);
    assert!(!format!("{restored_keys:?}").contains("195"));
    assert_eq!(reopened.sync_recovery_confirmation().unwrap().as_deref(), Some(paired_at.as_str()));
    let peers = reopened.list_sync_trusted_devices().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].device_id, peer_id);
    assert_eq!(peers[0].x25519_public_key, peer_key);
    assert_eq!(peers[0].ed25519_public_key, Some(peer_signing_key));
    assert!(peers[0].revoked_at.is_none());
    assert_eq!(peers[0].key_epoch, 2);
    let history = reopened.list_sync_device_access_history(10).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].action, "paired");
    reopened.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn lost_device_rekey_replaces_keys_revokes_atomically_and_invalidates_recovery() {
    let path = std::env::temp_dir().join(format!(
        "peakactivity-sync-rekey-{}.db",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), "c".repeat(64)).unwrap();
    let lost_device = [0x51; 16];
    let kept_device = [0x52; 16];
    let old = SyncKeyMaterial::new(
        Zeroizing::new([0x53; 32]), [0x54; 16], 2, [0x55; 24], [0x56; 48],
    );
    store.record_sync_pairing(
        Some(old), [0x57; 16], lost_device, [0x58; 32], [0x68; 32], "2026-09-23T12:00:00Z".into(),
    ).unwrap();
    store.record_sync_pairing(
        None, [0x59; 16], kept_device, [0x5A; 32], [0x6A; 32], "2026-09-23T12:01:00Z".into(),
    ).unwrap();
    let old_head = SyncManifestHeadV1::new(1, [0x5B; 32]);
    assert_eq!(store.commit_sync_manifest_head([0x54; 16], 2, lost_device, SyncManifestHeadV1::genesis(), old_head).unwrap(), SyncHeadCommitV1::Advanced);
    store.confirm_sync_recovery_saved("2026-09-23T12:02:00Z".into()).unwrap();

    let next = SyncKeyMaterial::new(
        Zeroizing::new([0x61; 32]), [0x54; 16], 3, [0x62; 24], [0x63; 48],
    );
    let next_snapshot = snapshot(3, [0x54; 16], 0xD0);
    assert!(store.rotate_sync_key_material(
        next.clone(), next_snapshot.clone(), Some(lost_device), "2026-09-23T12:03:00Z".into(),
    ).unwrap());

    let current = store.load_sync_key_material().unwrap().unwrap();
    assert_eq!(current.key_epoch(), 3);
    assert_eq!(&*current.account_root_key(), &[0x61; 32]);
    assert!(store.sync_recovery_confirmation().unwrap().is_none());
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(next_snapshot.clone()));
    assert_eq!(store.load_sync_manifest_head([0x54; 16], 2, lost_device).unwrap(), Some(old_head));
    assert!(store.load_sync_manifest_head([0x54; 16], 3, lost_device).unwrap().is_none());
    let peers = store.list_sync_trusted_devices().unwrap();
    assert_eq!(peers.len(), 2);
    assert_eq!(peers.iter().find(|peer| peer.device_id == lost_device).unwrap().revoked_at.as_deref(), Some("2026-09-23T12:03:00Z"));
    assert_eq!(peers.iter().find(|peer| peer.device_id == kept_device).unwrap().key_epoch, 2);
    assert_eq!(store.list_sync_device_access_history(10).unwrap()[0].action, "revoked");
    assert!(store.rotate_sync_key_material(
        SyncKeyMaterial::new(Zeroizing::new([0x64; 32]), [0x54; 16], 4, [0x65; 24], [0x66; 48]),
        snapshot(3, [0x54; 16], 0xD1), Some(kept_device), "2026-09-23T12:04:00Z".into(),
    ).is_err());
    assert_eq!(store.load_sync_key_material().unwrap().unwrap().key_epoch(), 3);
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(next_snapshot.clone()));
    assert!(store.list_sync_trusted_devices().unwrap().iter()
        .find(|peer| peer.device_id == kept_device).unwrap().revoked_at.is_none());
    assert!(!store.rotate_sync_key_material(
        SyncKeyMaterial::new(Zeroizing::new([0x64; 32]), [0x54; 16], 4, [0x65; 24], [0x66; 48]),
        snapshot(4, [0x54; 16], 0xD1), Some(lost_device), "2026-09-23T12:04:00Z".into(),
    ).unwrap());
    assert_eq!(store.load_sync_key_material().unwrap().unwrap().key_epoch(), 3);
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(next_snapshot));
    store.lock().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn recovered_sync_keys_and_snapshot_install_together_only_into_an_empty_sync_vault() {
    let store = memory_vault();
    let material = SyncKeyMaterial::new(
        Zeroizing::new([0x81; 32]), [0x82; 16], 2, [0x83; 24], [0x84; 48],
    );
    let encrypted_snapshot = snapshot(2, [0x82; 16], 0x85);
    assert!(store.install_sync_recovery(
        material.clone(), snapshot(1, [0x82; 16], 0x86),
    ).is_err());
    assert!(store.load_sync_key_material().unwrap().is_none());
    assert!(store.load_sync_snapshot().unwrap().is_none());

    store.install_sync_recovery(material.clone(), encrypted_snapshot.clone()).unwrap();
    assert_eq!(store.load_sync_key_material().unwrap().unwrap().key_epoch(), 2);
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(encrypted_snapshot));
    assert!(store.install_sync_recovery(material, snapshot(2, [0x82; 16], 0x87)).is_err());
    assert_eq!(store.load_sync_key_material().unwrap().unwrap().key_epoch(), 2);
    store.close();
}

#[test]
fn trusted_encrypted_snapshot_restore_preserves_original_activity_fields() {
    let store = memory_vault();
    store.enable_capture_policy().unwrap();
    let bucket_id = "aw-watcher-window_sync_restore".to_owned();
    let event = Event::new(
        Utc::now(),
        Duration::seconds(4),
        json!({"app":"Editor", "title":"restored-private-title", "path":"/private/project"})
            .as_object().unwrap().clone(),
    );
    let bucket = Bucket {
        bid: None,
        id: bucket_id.clone(),
        _type: "currentwindow".into(),
        client: "restore-test".into(),
        hostname: "source-device".into(),
        created: None,
        data: Default::default(),
        metadata: BucketMetadata::default(),
        events: Some(TryVec::new(vec![event.clone(), event])),
        last_updated: None,
    };
    let export = BucketsExport { buckets: HashMap::from([(bucket_id.clone(), bucket)]) };
    let duplicate_restore = export.clone();

    let imported = store.restore_sync_snapshot_data(export).unwrap();
    assert_eq!(imported.buckets_created, 1);
    assert_eq!(imported.events_imported, 2);
    assert_eq!(imported.events_skipped, 0);
    let events = store.get_events(&bucket_id, None, None, None).unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event.data["title"] == "restored-private-title"));
    assert!(events.iter().all(|event| event.data["path"] == "/private/project"));
    assert!(store.restore_sync_snapshot_data(duplicate_restore).is_err());
    assert_eq!(store.get_events(&bucket_id, None, None, None).unwrap().len(), 2);
    store.close();
}

#[test]
fn sync_session_requires_current_device_keys_snapshot_recovery_and_kill_switch_off() {
    let store = memory_vault();
    assert!(!store.sync_enabled().unwrap());
    assert!(store.set_sync_enabled(true, Some("sync-relay".into()), Some("sync-object-v1".into())).is_err());
    let device_id = [0xA1; 16];
    let vault_id = [0xA2; 16];
    store.record_sync_pairing(
        Some(SyncKeyMaterial::new(Zeroizing::new([0xA3; 32]), vault_id, 1, [0xA4; 24], [0xA5; 48])),
        [0xA6; 16], device_id, [0xA7; 32], [0xB7; 32], "2026-09-23T12:40:00Z".into(),
    ).unwrap();
    store.rotate_sync_key_material(
        SyncKeyMaterial::new(Zeroizing::new([0xA8; 32]), vault_id, 2, [0xA9; 24], [0xAA; 48]),
        snapshot(2, vault_id, 0xAB), None, "2026-09-23T12:41:00Z".into(),
    ).unwrap();
    assert!(store.set_sync_enabled(true, Some("sync-relay".into()), Some("sync-object-v1".into())).is_err());
    store.record_sync_pairing(None, [0xAC; 16], device_id, [0xA7; 32], [0xB7; 32], "2026-09-23T12:42:00Z".into()).unwrap();
    store.confirm_sync_recovery_saved("2026-09-23T12:43:00Z".into()).unwrap();
    assert!(store.set_sync_enabled(true, Some("sync-relay".into()), Some("sync-object-v1".into())).is_err());
    store.set_egress_kill_switch(false).unwrap();
    store.set_sync_enabled(true, Some("sync-relay".into()), Some("sync-object-v1".into())).unwrap();
    assert!(store.sync_enabled().unwrap());
    assert_eq!(store.sync_egress_consent().unwrap().unwrap().destination_id, "sync-relay");
    store.rotate_sync_key_material(
        SyncKeyMaterial::new(Zeroizing::new([0xAC; 32]), vault_id, 3, [0xAD; 24], [0xAE; 48]),
        snapshot(3, vault_id, 0xAF), None, "2026-09-23T12:44:00Z".into(),
    ).unwrap();
    assert!(!store.sync_enabled().unwrap());
    assert!(store.sync_egress_consent().unwrap().is_none());
    assert!(store.sync_recovery_confirmation().unwrap().is_none());
    store.set_sync_enabled(false, None, None).unwrap();
    assert!(!store.sync_enabled().unwrap());
    store.close();
}
