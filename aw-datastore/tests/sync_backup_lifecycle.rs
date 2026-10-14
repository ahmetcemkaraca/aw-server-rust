#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::{Datastore, SyncKeyMaterial, SyncSnapshotV1};
use aw_sync_e2ee::{
    create_vault_data_key, encrypt_snapshot, generate_account_root_key, EncryptedSyncSnapshotV1,
    SnapshotDeletionProofV1, VaultDataKeyV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
const AT: &str = "2026-10-14T12:00:00Z";
fn native(snapshot: &EncryptedSyncSnapshotV1) -> SyncSnapshotV1 {
    SyncSnapshotV1::new(
        URL_SAFE_NO_PAD
            .decode(&snapshot.snapshot_id)
            .unwrap()
            .try_into()
            .unwrap(),
        snapshot.envelopes.clone(),
    )
}
fn source(
    path: &str,
) -> (
    Datastore,
    VaultDataKeyV1,
    SyncKeyMaterial,
    EncryptedSyncSnapshotV1,
    EncryptedSyncSnapshotV1,
) {
    let store = Datastore::open_encrypted(path.into(), "a".repeat(64)).unwrap();
    let root = generate_account_root_key().unwrap();
    let (key, wrapped) =
        create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x71; 16]), 1).unwrap();
    let material = SyncKeyMaterial::new(
        root.secret_for_storage(),
        [0x71; 16],
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
    let old = encrypt_snapshot(&key, b"old private payload").unwrap();
    let current = encrypt_snapshot(&key, b"current private payload").unwrap();
    store.install_sync_key_material(&material).unwrap();
    store
        .save_sync_snapshot(material.clone(), native(&old))
        .unwrap();
    for object in &old.envelopes {
        store.put_sync_object(object.clone(), AT.into()).unwrap();
    }
    store
        .save_sync_snapshot(material.clone(), native(&current))
        .unwrap();
    store.set_key_value("settings.theme", "\"dark\"").unwrap();
    (store, key, material, old, current)
}
#[test]
fn backup_delete_exact_history_is_atomic_and_deleted_bytes_cannot_return() {
    let (store, key, material, old, current) = source(":memory:");
    let context = store.get_sync_policy_context().unwrap().context_id;
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let expected = proof.fact().clone();
    assert_eq!(
        store
            .delete_sync_backup(context.clone(), proof, AT.into())
            .unwrap(),
        1
    );
    assert!(store
        .get_sync_object(old.envelopes[0].object_id.clone())
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
            .unwrap(),
        Some(expected)
    );
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
    assert_eq!(store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert!(store
        .put_sync_object(old.envelopes[0].clone(), AT.into())
        .is_err());
    assert!(store
        .stage_sync_backup_objects(context.clone(), old.envelopes.clone(), AT.into())
        .is_err());
    assert!(store.save_sync_snapshot(material, native(&old)).is_err());
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
    let repeat = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    assert_eq!(
        store
            .delete_sync_backup(context, repeat, AT.into())
            .unwrap(),
        0
    );
    store.close();
}
#[test]
fn backup_delete_current_overlap_and_stale_context_preserve_everything() {
    let (store, key, _, old, current) = source(":memory:");
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let before = store.list_sync_object_history(1000).unwrap();
    let current_proof = SnapshotDeletionProofV1::authenticate(&key, &current).unwrap();
    assert!(store
        .delete_sync_backup(ctx.clone(), current_proof, AT.into())
        .is_err());
    let old_proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    assert!(store
        .delete_sync_backup("0".repeat(64), old_proof, AT.into())
        .is_err());
    assert_eq!(store.list_sync_object_history(1000).unwrap(), before);
    assert!(store
        .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
        .unwrap()
        .is_none());
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
    assert_eq!(
        store
            .get_sync_object(old.envelopes[0].object_id.clone())
            .unwrap(),
        Some(old.envelopes[0].clone())
    );
    store.close();
}
#[test]
fn backup_delete_late_conflict_does_not_create_a_marker_or_remove_any_object() {
    let (store, key, _, old, current) = source(":memory:");
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let different = encrypt_snapshot(&key, b"same scope, different object bytes").unwrap();
    let absent = SnapshotDeletionProofV1::authenticate(&key, &different).unwrap();
    assert!(store.delete_sync_backup(ctx, absent, AT.into()).is_err());
    assert!(store
        .get_sync_backup_deletion(different.envelopes[0].object_id.clone())
        .unwrap()
        .is_none());
    assert!(store
        .get_sync_object(old.envelopes[0].object_id.clone())
        .unwrap()
        .is_some());
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
    store.close();
}
#[test]
fn backup_delete_real_trigger_and_commit_failure_preserve_rows_and_facts_after_reopen() {
    for deferred in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "peak-backup-delete-{}-{}-{deferred}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let (store, key, _, old, current) = source(path.to_str().unwrap());
        store.close();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.pragma_update(None, "key", "a".repeat(64)).unwrap();
        if deferred {
            db.execute_batch("CREATE TABLE delete_parent(id INTEGER PRIMARY KEY);CREATE TABLE delete_child(id INTEGER REFERENCES delete_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_backup_delete AFTER DELETE ON sync_objects BEGIN INSERT INTO delete_child(id) VALUES(1); END;").unwrap();
        } else {
            db.execute_batch("CREATE TRIGGER fail_backup_delete BEFORE DELETE ON sync_objects BEGIN SELECT RAISE(ABORT,'synthetic delete failure'); END;").unwrap();
        }
        drop(db);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
        let ctx = store.get_sync_policy_context().unwrap().context_id;
        let error = store
            .delete_sync_backup(
                ctx,
                SnapshotDeletionProofV1::authenticate(&key, &old).unwrap(),
                AT.into(),
            )
            .unwrap_err();
        if deferred {
            assert!(
                format!("{error:?}").to_lowercase().contains("commit"),
                "must fail at actual COMMIT: {error:?}"
            );
        }
        store.close();
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
        assert_eq!(
            store
                .get_sync_object(old.envelopes[0].object_id.clone())
                .unwrap(),
            Some(old.envelopes[0].clone())
        );
        assert!(store
            .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
            .unwrap()
            .is_none());
        assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
        store.close();
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn backup_delete_schema14_migration_preserves_existing_ciphertext_and_keys() {
    let path = std::env::temp_dir().join(format!(
        "peak-backup-migrate-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (store, _, material, old, current) = source(path.to_str().unwrap());
    store.close();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "key", "a".repeat(64)).unwrap();
    db.execute_batch("DROP TABLE sync_backup_deleted_objects;DROP TABLE sync_backup_deletions;PRAGMA user_version=14;").unwrap();
    drop(db);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    assert_eq!(
        store
            .get_sync_object(old.envelopes[0].object_id.clone())
            .unwrap(),
        Some(old.envelopes[0].clone())
    );
    assert!(store
        .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
        .unwrap()
        .is_none());
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
    assert_eq!(
        store
            .load_sync_key_material()
            .unwrap()
            .unwrap()
            .account_root_key(),
        material.account_root_key()
    );
    store.close();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "key", "a".repeat(64)).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        16
    );
    drop(db);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn backup_delete_changed_second_ciphertext_preserves_first_chunk_and_all_markers() {
    let path = std::env::temp_dir().join(format!(
        "peak-backup-conflict-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (store, key, _, _, current) = source(path.to_str().unwrap());
    let old = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    for object in &old.envelopes {
        store.put_sync_object(object.clone(), AT.into()).unwrap();
    }
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    store.close();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "key", "a".repeat(64)).unwrap();
    db.execute(
        "UPDATE sync_objects SET nonce=?1 WHERE object_id=?2",
        rusqlite::params![URL_SAFE_NO_PAD.encode([9; 24]), old.envelopes[1].object_id],
    )
    .unwrap();
    drop(db);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), "a".repeat(64)).unwrap();
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    assert!(store.delete_sync_backup(ctx, proof, AT.into()).is_err());
    assert_eq!(
        store
            .get_sync_object(old.envelopes[0].object_id.clone())
            .unwrap(),
        Some(old.envelopes[0].clone())
    );
    for object in old.envelopes {
        assert!(store
            .get_sync_backup_deletion(object.object_id)
            .unwrap()
            .is_none());
    }
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
    store.close();
    std::fs::remove_file(path).unwrap();
}
#[test]
fn backup_delete_facts_survive_fresh_snapshot_and_real_key_rotation() {
    let (store, key, material, old, _) = source(":memory:");
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    let proof = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let fact = proof.fact().clone();
    store.delete_sync_backup(ctx, proof, AT.into()).unwrap();
    let fresh = encrypt_snapshot(&key, b"fresh snapshot after explicit deletion").unwrap();
    store.save_sync_snapshot(material, native(&fresh)).unwrap();
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&fresh)));
    let root = generate_account_root_key().unwrap();
    let (next, wrapped) =
        create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode(key.vault_id()), 2).unwrap();
    let next_material = SyncKeyMaterial::new(
        root.secret_for_storage(),
        key.vault_id(),
        2,
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
    let next_snapshot = encrypt_snapshot(&next, b"new epoch private activity").unwrap();
    assert!(store
        .rotate_sync_key_material(next_material, native(&next_snapshot), None, AT.into())
        .unwrap());
    assert_eq!(
        store
            .get_sync_backup_deletion(old.envelopes[0].object_id.clone())
            .unwrap(),
        Some(fact)
    );
    assert!(store
        .put_sync_object(old.envelopes[0].clone(), AT.into())
        .is_err());
    assert_eq!(
        store.load_sync_snapshot().unwrap(),
        Some(native(&next_snapshot))
    );
    store.close();
}
#[test]
fn backup_delete_partial_resume_cannot_establish_a_new_intent() {
    let (store, key, _, _, current) = source(":memory:");
    let old = encrypt_snapshot(&key, &vec![7; 1_100_000]).unwrap();
    for object in &old.envelopes {
        store.put_sync_object(object.clone(), AT.into()).unwrap();
    }
    let complete = SnapshotDeletionProofV1::authenticate(&key, &old).unwrap();
    let record = complete.seal(&key).unwrap();
    let partial = SnapshotDeletionProofV1::resume(&key, &record, &old.envelopes[1..]).unwrap();
    assert!(!partial.is_complete());
    let ctx = store.get_sync_policy_context().unwrap().context_id;
    assert!(store.delete_sync_backup(ctx, partial, AT.into()).is_err());
    for object in &old.envelopes {
        assert_eq!(
            store.get_sync_object(object.object_id.clone()).unwrap(),
            Some(object.clone())
        );
        assert!(store
            .get_sync_backup_deletion(object.object_id.clone())
            .unwrap()
            .is_none());
    }
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(native(&current)));
    store.close();
}
#[test]
fn backup_delete_controls_require_an_actual_encrypted_worker() {
    let plain = Datastore::new_in_memory(false);
    let root = generate_account_root_key().unwrap();
    let (key, _) = create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode([0x71; 16]), 1).unwrap();
    let snapshot = encrypt_snapshot(&key, b"synthetic private").unwrap();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    assert!(plain
        .delete_sync_backup("0".repeat(64), proof, AT.into())
        .is_err());
    assert!(plain
        .get_sync_backup_deletion(snapshot.envelopes[0].object_id.clone())
        .is_err());
    plain.close();
}
