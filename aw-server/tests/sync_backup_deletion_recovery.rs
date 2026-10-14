#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[path = "support/backup_provider.rs"]
mod fixture;
use aw_datastore::Datastore;
use aw_server::sync_control::SyncControl;
use aw_sync_e2ee::{
    unwrap_vault_data_key, AccountRootKeyV1, EncryptedSyncSnapshotV1, SnapshotDeletionProofV1,
    WrappedVaultDataKeyV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
fn encrypted(store: &Datastore) -> EncryptedSyncSnapshotV1 {
    let s = store.load_sync_snapshot().unwrap().unwrap();
    EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(s.snapshot_id),
        envelopes: s.envelopes,
    }
}
fn key(store: &Datastore) -> aw_sync_e2ee::VaultDataKeyV1 {
    let m = store.load_sync_key_material().unwrap().unwrap();
    unwrap_vault_data_key(
        &AccountRootKeyV1::from_bytes(zeroize::Zeroizing::new(*m.account_root_key())),
        &WrappedVaultDataKeyV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(m.vault_id()),
            key_epoch: m.key_epoch(),
            nonce: URL_SAFE_NO_PAD.encode(m.wrapped_nonce()),
            ciphertext: URL_SAFE_NO_PAD.encode(m.wrapped_ciphertext()),
        },
    )
    .unwrap()
}
#[test]
fn backup_deletion_recovery_export_carries_facts_and_restore_preserves_target_newer_facts() {
    let (source, kit, _) = fixture::source();
    let key = key(&source);
    let old = encrypted(&source);
    let control = SyncControl::new();
    control
        .invoke(&source, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let source_fact = proof.fact().clone();
    source
        .delete_sync_backup(
            source.get_sync_policy_context().unwrap().context_id,
            proof,
            "2026-10-14T12:00:00Z".into(),
        )
        .unwrap();
    control
        .invoke(&source, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let snapshot = encrypted(&source);
    let payload: Value =
        serde_json::from_slice(&aw_sync_e2ee::decrypt_snapshot(&key, &snapshot).unwrap()).unwrap();
    assert_eq!(
        payload["sync"]["backup_deletions"],
        json!([source_fact.clone()])
    );
    let target = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    target.enable_capture_policy().unwrap();
    target.pause_capture().unwrap();
    let other = aw_sync_e2ee::encrypt_snapshot(&key, b"another known target deletion").unwrap();
    let target_fact = SnapshotDeletionProofV1::authenticate(&key, &other)
        .unwrap()
        .fact()
        .clone();
    target
        .merge_sync_backup_deletions(
            target.get_sync_policy_context().unwrap().context_id,
            vec![target_fact.clone()],
            "2026-10-14T12:01:00Z".into(),
        )
        .unwrap();
    let args = json!({"kit":kit["kit"],"recoveryPhrase":kit["recovery_phrase"],"snapshot":snapshot,"userAccepted":true});
    control
        .invoke(
            &target,
            "preview_sync_recovery_restore",
            args.as_object()
                .unwrap()
                .iter()
                .filter(|(k, _)| *k != "userAccepted")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<serde_json::Map<String, Value>>()
                .into(),
        )
        .unwrap();
    control
        .invoke(&target, "restore_sync_recovery_kit", args)
        .unwrap();
    let facts = target
        .export_sync_backup_deletions(target.get_sync_policy_context().unwrap().context_id)
        .unwrap();
    assert!(facts.contains(&source_fact));
    assert!(facts.contains(&target_fact));
    assert_eq!(facts.len(), 2);
    assert!(!target.capture_policy().unwrap().recording);
    assert!(!target.sync_enabled().unwrap());
    source.close();
    target.close();
}
#[test]
fn backup_deletion_recovery_known_deleted_raw_snapshot_refuses_preview_and_install() {
    let (source, kit, _) = fixture::source();
    let key = key(&source);
    let snapshot = encrypted(&source);
    let fact = SnapshotDeletionProofV1::authenticate(&key, &snapshot)
        .unwrap()
        .fact()
        .clone();
    let target = Datastore::open_encrypted(":memory:".into(), "b".repeat(64)).unwrap();
    target.enable_capture_policy().unwrap();
    target.pause_capture().unwrap();
    target
        .merge_sync_backup_deletions(
            target.get_sync_policy_context().unwrap().context_id,
            vec![fact],
            "2026-10-14T12:00:00Z".into(),
        )
        .unwrap();
    let control = SyncControl::new();
    let preview =
        json!({"kit":kit["kit"],"recoveryPhrase":kit["recovery_phrase"],"snapshot":snapshot});
    assert!(control
        .invoke(&target, "preview_sync_recovery_restore", preview.clone())
        .is_err());
    let mut accepted = preview;
    accepted["userAccepted"] = json!(true);
    assert!(control
        .invoke(&target, "restore_sync_recovery_kit", accepted)
        .is_err());
    assert!(target.get_buckets().unwrap().is_empty());
    assert!(target.load_sync_key_material().unwrap().is_none());
    assert!(target.load_sync_snapshot().unwrap().is_none());
    source.close();
    target.close();
}
#[test]
fn backup_deletion_recovery_legacy_empty_and_malformed_fact_payloads_are_distinct() {
    let (source, _, _) = fixture::source();
    let key = key(&source);
    let current = encrypted(&source);
    let original: Value =
        serde_json::from_slice(&aw_sync_e2ee::decrypt_snapshot(&key, &current).unwrap()).unwrap();
    let other = aw_sync_e2ee::encrypt_snapshot(&key, b"known other artifact").unwrap();
    let fact = SnapshotDeletionProofV1::authenticate(&key, &other)
        .unwrap()
        .fact()
        .clone();
    let mut legacy = original.clone();
    legacy["sync"]
        .as_object_mut()
        .unwrap()
        .remove("backup_deletions");
    let encrypted =
        aw_sync_e2ee::encrypt_snapshot(&key, &serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert!(
        aw_server::sync_control::decrypt_recovery_snapshot(&key, &encrypted)
            .unwrap()
            .sync
            .backup_deletions
            .is_empty()
    );
    for bad in [
        json!(null),
        json!([{"schema_version":1}]),
        {
            let mut conflict = fact.clone();
            conflict.bundle_sha256 = "f".repeat(64);
            json!([fact.clone(), conflict])
        },
        {
            let mut malformed = fact.clone();
            malformed.key_epoch = "01".into();
            json!([malformed])
        },
    ] {
        let mut data = original.clone();
        data["sync"]["backup_deletions"] = bad;
        let encrypted =
            aw_sync_e2ee::encrypt_snapshot(&key, &serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(aw_server::sync_control::decrypt_recovery_snapshot(&key, &encrypted).is_err());
    }
    source.close();
}
#[test]
fn backup_deletion_recovery_cannot_declare_its_own_artifact_deleted() {
    let (source, _, _) = fixture::source();
    let key = key(&source);
    let current = encrypted(&source);
    let mut payload: Value =
        serde_json::from_slice(&aw_sync_e2ee::decrypt_snapshot(&key, &current).unwrap()).unwrap();
    let snapshot_id = [0x41; 16];
    let object_id = [0x42; 16];
    let mut fact = SnapshotDeletionProofV1::authenticate(&key, &current)
        .unwrap()
        .fact()
        .clone();
    fact.snapshot_id = URL_SAFE_NO_PAD.encode(snapshot_id);
    fact.objects[0].object_id = URL_SAFE_NO_PAD.encode(object_id);
    payload["sync"]["backup_deletions"] = json!([fact]);
    let mut bytes = b"PeakActivity-Sync-Snapshot-v1\0".to_vec();
    bytes.extend_from_slice(&snapshot_id);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend(serde_json::to_vec(&payload).unwrap());
    let envelope = aw_sync_e2ee::encrypt_chunk(
        &key,
        &aw_models::SyncChunkHeaderV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode(object_id),
            vault_id: URL_SAFE_NO_PAD.encode(key.vault_id()),
            key_epoch: 1,
        },
        &bytes,
    )
    .unwrap();
    let snapshot = EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(snapshot_id),
        envelopes: vec![envelope],
    };
    assert!(aw_server::sync_control::decrypt_recovery_snapshot(&key, &snapshot).is_err());
    source.close();
}
