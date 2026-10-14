#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::{Datastore, SyncKeyMaterial, SyncSnapshotV1};
use aw_sync_e2ee::{
    create_vault_data_key, encrypt_snapshot, generate_account_root_key, SnapshotDeletionProofV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
const AT: &str = "2026-10-14T12:00:00Z";
fn fixture(
    path: &str,
) -> (
    Datastore,
    aw_sync_e2ee::VaultDataKeyV1,
    aw_sync_e2ee::EncryptedSyncSnapshotV1,
    SyncSnapshotV1,
) {
    let store = Datastore::open_encrypted(path.into(), "a".repeat(64)).unwrap();
    let root = generate_account_root_key().unwrap();
    let (key, wrapped) = create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([1; 16]), 1).unwrap();
    let material = SyncKeyMaterial::new(
        root.secret_for_storage(),
        key.vault_id(),
        1,
        URL_SAFE_NO_PAD
            .decode(wrapped.nonce)
            .unwrap()
            .try_into()
            .unwrap(),
        URL_SAFE_NO_PAD
            .decode(wrapped.ciphertext)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    store.install_sync_key_material(&material).unwrap();
    let old = encrypt_snapshot(&key, b"folder-only historical version").unwrap();
    let current = encrypt_snapshot(&key, b"protected local current version").unwrap();
    let snapshot = SyncSnapshotV1::new(
        URL_SAFE_NO_PAD
            .decode(current.snapshot_id)
            .unwrap()
            .try_into()
            .unwrap(),
        current.envelopes,
    );
    store
        .save_sync_snapshot(material, snapshot.clone())
        .unwrap();
    (store, key, old, snapshot)
}
#[test]
fn accepted_backup_intent_records_folder_only_proof_before_io_without_changing_current_or_keys() {
    let path = std::env::temp_dir().join(format!(
        "peak-folder-intent-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (store, key, old, current) = fixture(path.to_str().unwrap());
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let fact = proof.fact().clone();
    assert!(store
        .get_sync_object(old.envelopes[0].object_id.clone())
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .record_sync_backup_deletion_intent(
                store.get_sync_policy_context().unwrap().context_id,
                proof,
                AT.into()
            )
            .unwrap(),
        1
    );
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(current));
    assert!(store.load_sync_key_material().unwrap().is_some());
    assert!(!store.sync_enabled().unwrap());
    assert!(store.load_sync_device_identity().unwrap().is_none());
    store.close();
    let reopened =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    assert_eq!(
        reopened
            .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
            .unwrap(),
        Some(fact)
    );
    assert!(reopened
        .put_sync_object(old.envelopes[0].clone(), AT.into())
        .is_err());
    reopened.close();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn accepted_backup_intent_refuses_current_stale_context_and_different_local_bytes() {
    let (store, key, old, current) = fixture(":memory:");
    let current = aw_sync_e2ee::EncryptedSyncSnapshotV1 {
        schema_version: 1,
        snapshot_id: URL_SAFE_NO_PAD.encode(current.snapshot_id),
        envelopes: current.envelopes,
    };
    let context = store.get_sync_policy_context().unwrap().context_id;
    assert!(store
        .record_sync_backup_deletion_intent(
            context.clone(),
            SnapshotDeletionProofV1::authenticate(&key, &current).unwrap(),
            AT.into()
        )
        .is_err());
    assert!(store
        .record_sync_backup_deletion_intent(
            "0".repeat(64),
            SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
            AT.into()
        )
        .is_err());
    let mut changed = old.envelopes[0].clone();
    changed.nonce = URL_SAFE_NO_PAD.encode([0x44; 24]);
    store.put_sync_object(changed.clone(), AT.into()).unwrap();
    assert!(store
        .record_sync_backup_deletion_intent(
            context.clone(),
            SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
            AT.into()
        )
        .is_err());
    assert!(store
        .export_sync_backup_deletions(context)
        .unwrap()
        .is_empty());
    assert_eq!(
        store.get_sync_object(changed.object_id.clone()).unwrap(),
        Some(changed)
    );
    store.close();
}
#[test]
fn accepted_backup_intent_never_removes_present_historical_ciphertext_and_retry_is_idempotent() {
    let (store, key, old, _) = fixture(":memory:");
    store
        .put_sync_object(old.envelopes[0].clone(), AT.into())
        .unwrap();
    let context = store.get_sync_policy_context().unwrap().context_id;
    assert_eq!(
        store
            .record_sync_backup_deletion_intent(
                context.clone(),
                SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
                AT.into()
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .record_sync_backup_deletion_intent(
                context.clone(),
                SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
                AT.into()
            )
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .get_sync_object(old.envelopes[0].object_id.clone())
            .unwrap(),
        Some(old.envelopes[0].clone())
    );
    assert_eq!(
        store
            .delete_sync_backup(
                context,
                SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
                AT.into()
            )
            .unwrap(),
        1
    );
    store.close();
}
#[test]
fn accepted_backup_intent_partial_proof_requires_identical_previously_committed_intent() {
    let (store, key, _, _) = fixture(":memory:");
    let old = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    let complete = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let sealed = complete.seal(&key).unwrap();
    let context = store.get_sync_policy_context().unwrap().context_id;
    let partial = SnapshotDeletionProofV1::resume(&key, &sealed, &old.envelopes[..1]).unwrap();
    assert!(store
        .record_sync_backup_deletion_intent(context.clone(), partial, AT.into())
        .is_err());
    store
        .record_sync_backup_deletion_intent(context.clone(), complete, AT.into())
        .unwrap();
    let partial = SnapshotDeletionProofV1::resume(&key, &sealed, &old.envelopes[..1]).unwrap();
    assert_eq!(
        store
            .record_sync_backup_deletion_intent(context, partial, AT.into())
            .unwrap(),
        0
    );
    store.close();
}
#[test]
fn accepted_backup_intent_rejects_plain_worker_and_ack_waits_for_deferred_commit() {
    let plain = Datastore::new_in_memory(false);
    let (unused, key, old, _) = fixture(":memory:");
    unused.close();
    assert!(plain
        .record_sync_backup_deletion_intent(
            "0".repeat(64),
            SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
            AT.into()
        )
        .is_err());
    plain.close();
    let path = std::env::temp_dir().join(format!(
        "peak-intent-deferred-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (setup, key, old, _) = fixture(path.to_str().unwrap());
    setup.close();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "key", "a".repeat(64))
        .unwrap();
    connection.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE intent_guard_parent(id INTEGER PRIMARY KEY); CREATE TABLE intent_guard_child(parent INTEGER REFERENCES intent_guard_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_intent_commit AFTER INSERT ON sync_backup_deletions BEGIN INSERT INTO intent_guard_child VALUES(1); END;").unwrap();
    drop(connection);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let error = store
        .record_sync_backup_deletion_intent(
            store.get_sync_policy_context().unwrap().context_id,
            SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
            AT.into(),
        )
        .unwrap_err();
    assert!(format!("{error:?}").contains("commit"));
    store.close();
    let reopened =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    assert!(reopened
        .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
        .unwrap()
        .is_none());
    reopened.close();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn accepted_backup_intent_partial_external_retry_preserves_the_full_local_copy() {
    let (store, key, _, _) = fixture(":memory:");
    let old = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    for object in &old.envelopes {
        store.put_sync_object(object.clone(), AT.into()).unwrap();
    }
    let complete = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let sealed = complete.seal(&key).unwrap();
    let context = store.get_sync_policy_context().unwrap().context_id;
    store
        .record_sync_backup_deletion_intent(context.clone(), complete, AT.into())
        .unwrap();
    let partial = SnapshotDeletionProofV1::resume(&key, &sealed, &old.envelopes[1..]).unwrap();
    assert_eq!(
        store
            .record_sync_backup_deletion_intent(context, partial, AT.into())
            .unwrap(),
        0
    );
    for object in old.envelopes {
        assert_eq!(
            store.get_sync_object(object.object_id.clone()).unwrap(),
            Some(object)
        );
    }
    store.close();
}

#[test]
fn provider_retry_record_survives_reopen_and_rejects_unbound_record() {
    let path = std::env::temp_dir().join(format!(
        "peak-provider-intent-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (store, key, old, _) = fixture(path.to_str().unwrap());
    let context = store.get_sync_policy_context().unwrap().context_id;
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let fact = proof.fact().clone();
    let record = proof.seal(&key).unwrap();
    let wrong = encrypt_snapshot(&key, b"ordinary encrypted snapshot").unwrap();
    assert!(store
        .record_sync_backup_provider_intent(context.clone(), proof, &key, wrong, AT.into())
        .is_err());
    assert!(store
        .export_sync_backup_deletions(context.clone())
        .unwrap()
        .is_empty());
    store
        .record_sync_backup_provider_intent(
            context,
            SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
            &key,
            record,
            AT.into(),
        )
        .unwrap();
    store.close();
    let reopened =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let context = reopened.get_sync_policy_context().unwrap().context_id;
    let lease = reopened.egress_lease().unwrap();
    let record = lease
        .sync_backup_provider_intent(context.clone(), fact.bundle_sha256.clone())
        .unwrap()
        .unwrap();
    assert_eq!(
        SnapshotDeletionProofV1::open_record(&key, &record).unwrap(),
        fact
    );
    assert!(lease
        .sync_backup_provider_intent("0".repeat(64), fact.bundle_sha256)
        .is_err());
    drop(lease);
    reopened.close();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn provider_retry_record_write_failure_rolls_back_fact_and_markers() {
    let path = std::env::temp_dir().join(format!(
        "peak-provider-intent-rollback-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (store, key, old, _) = fixture(path.to_str().unwrap());
    store.close();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "key", "a".repeat(64)).unwrap();
    db.execute_batch("CREATE TRIGGER reject_provider_record BEFORE UPDATE OF sealed_record_json ON sync_backup_deletions BEGIN SELECT RAISE(ABORT,'synthetic'); END;").unwrap();
    drop(db);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let context = store.get_sync_policy_context().unwrap().context_id;
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let record = proof.seal(&key).unwrap();
    assert!(store
        .record_sync_backup_provider_intent(context.clone(), proof, &key, record, AT.into())
        .is_err());
    assert!(store
        .export_sync_backup_deletions(context)
        .unwrap()
        .is_empty());
    assert!(store
        .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
        .unwrap()
        .is_none());
    store.close();
    std::fs::remove_file(path).unwrap();
}
