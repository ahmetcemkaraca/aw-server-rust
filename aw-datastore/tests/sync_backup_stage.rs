#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::{Datastore, SyncKeyMaterial, SyncSnapshotV1};
use aw_models::SyncEnvelopeV1;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
const AT: &str = "2026-10-14T12:00:00Z";

fn object(id: u8) -> SyncEnvelopeV1 {
    SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([id; 16]),
        vault_id: URL_SAFE_NO_PAD.encode([0x71; 16]),
        key_epoch: 1,
        nonce: URL_SAFE_NO_PAD.encode([id; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([id; 32]),
    }
}
fn store() -> Datastore {
    Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap()
}

#[test]
fn backup_stage_is_atomic_idempotent_and_changes_only_ciphertext_objects() {
    let store = store();
    store.set_key_value("settings.theme", "\"dark\"").unwrap();
    let context = store.get_sync_policy_context().unwrap().context_id;
    let a = object(1);
    let b = object(2);
    assert_eq!(
        store
            .stage_sync_backup_objects(context.clone(), vec![a.clone(), b.clone()], AT.into())
            .unwrap(),
        2
    );
    assert_eq!(
        store
            .stage_sync_backup_objects(context, vec![a.clone(), b], AT.into())
            .unwrap(),
        0
    );
    assert_eq!(store.get_sync_object(a.object_id.clone()).unwrap(), Some(a));
    assert_eq!(store.list_sync_object_history(1000).unwrap().len(), 2);
    assert!(store.load_sync_key_material().unwrap().is_none());
    assert!(store.load_sync_snapshot().unwrap().is_none());
    assert!(store.load_sync_device_identity().unwrap().is_none());
    assert!(store.get_buckets().unwrap().is_empty());
    assert_eq!(store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert!(!store.sync_enabled().unwrap());
    store.close();
}

#[test]
fn backup_stage_stale_context_or_late_immutable_conflict_preserves_whole_target() {
    let store = store();
    let context = store.get_sync_policy_context().unwrap().context_id;
    let a = object(1);
    let b = object(2);
    store.put_sync_object(a.clone(), AT.into()).unwrap();
    let before = store.list_sync_object_history(1000).unwrap();
    let mut conflict = a.clone();
    conflict.ciphertext = URL_SAFE_NO_PAD.encode([9; 32]);
    assert!(store
        .stage_sync_backup_objects(context.clone(), vec![b.clone(), conflict], AT.into())
        .is_err());
    assert!(store
        .get_sync_object(b.object_id.clone())
        .unwrap()
        .is_none());
    assert_eq!(store.list_sync_object_history(1000).unwrap(), before);
    assert!(store
        .stage_sync_backup_objects("wrong-context".into(), vec![b.clone()], AT.into())
        .is_err());
    assert!(store
        .get_sync_object(b.object_id.clone())
        .unwrap()
        .is_none());
    store.close();
    store
        .unlock_encrypted(":memory:".into(), "b".repeat(64))
        .unwrap();
    assert!(store
        .stage_sync_backup_objects(context, vec![b.clone()], AT.into())
        .is_err());
    assert!(store.get_sync_object(b.object_id).unwrap().is_none());
    store.close();
}

#[test]
fn backup_stage_rejects_unsupported_epoch_bad_time_and_duplicate_conflict_before_mutation() {
    let store = store();
    let context = store.get_sync_policy_context().unwrap().context_id;
    let a = object(1);
    let mut unsupported = object(2);
    unsupported.key_epoch = u64::MAX;
    assert!(store
        .stage_sync_backup_objects(context.clone(), vec![a.clone(), unsupported], AT.into())
        .is_err());
    assert!(store
        .stage_sync_backup_objects(context.clone(), vec![a.clone()], "invalid-time".into())
        .is_err());
    let mut conflict = a.clone();
    conflict.nonce = URL_SAFE_NO_PAD.encode([8; 24]);
    assert!(store
        .stage_sync_backup_objects(context, vec![a.clone(), conflict], AT.into())
        .is_err());
    assert!(store.get_sync_object(a.object_id).unwrap().is_none());
    assert!(store.list_sync_object_history(1000).unwrap().is_empty());
    store.close();
}

#[test]
fn backup_stage_current_pointer_conflict_cannot_replace_keys_or_current_snapshot() {
    let store = store();
    let context = store.get_sync_policy_context().unwrap().context_id;
    let a = object(1);
    let b = object(2);
    let material = SyncKeyMaterial::new(
        zeroize::Zeroizing::new([7; 32]),
        [0x71; 16],
        1,
        [8; 24],
        [9; 48],
    );
    let snapshot = SyncSnapshotV1::new([6; 16], vec![a.clone()]);
    store.install_sync_key_material(&material).unwrap();
    store
        .save_sync_snapshot(material, snapshot.clone())
        .unwrap();
    let mut conflict = a;
    conflict.ciphertext = URL_SAFE_NO_PAD.encode([10; 32]);
    assert!(store
        .stage_sync_backup_objects(context, vec![b.clone(), conflict], AT.into())
        .is_err());
    assert!(store.get_sync_object(b.object_id).unwrap().is_none());
    assert_eq!(store.load_sync_snapshot().unwrap(), Some(snapshot));
    assert_eq!(
        store
            .load_sync_key_material()
            .unwrap()
            .unwrap()
            .account_root_key(),
        &[7; 32]
    );
    store.close();
}

#[test]
fn backup_stage_real_insert_and_deferred_commit_failures_never_ack_or_leave_partial_objects() {
    for deferred in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "peak-backup-stage-{}-{}-{deferred}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = "c".repeat(64);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        store.set_key_value("settings.theme", "\"dark\"").unwrap();
        store.close();
        let a = object(1);
        let b = object(2);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "key", key.as_str()).unwrap();
        if deferred {
            conn.execute_batch(&format!("CREATE TABLE backup_parent(id INTEGER PRIMARY KEY);CREATE TABLE backup_child(parent_id INTEGER NOT NULL REFERENCES backup_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_backup_stage AFTER INSERT ON sync_objects WHEN NEW.object_id='{}' BEGIN INSERT INTO backup_child(parent_id) VALUES(1); END;",b.object_id)).unwrap();
        } else {
            conn.execute_batch(&format!("CREATE TRIGGER fail_backup_stage BEFORE INSERT ON sync_objects WHEN NEW.object_id='{}' BEGIN SELECT RAISE(ABORT,'synthetic backup stage failure'); END;",b.object_id)).unwrap();
        }
        drop(conn);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        let context = store.get_sync_policy_context().unwrap().context_id;
        assert!(store
            .stage_sync_backup_objects(context, vec![a.clone(), b.clone()], AT.into())
            .is_err());
        store.close();
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        assert!(store
            .get_sync_object(a.object_id.clone())
            .unwrap()
            .is_none());
        assert!(store
            .get_sync_object(b.object_id.clone())
            .unwrap()
            .is_none());
        assert!(store.list_sync_object_history(1000).unwrap().is_empty());
        assert!(store.load_sync_snapshot().unwrap().is_none());
        assert!(store.load_sync_key_material().unwrap().is_none());
        assert_eq!(store.get_key_value("settings.theme").unwrap(), "\"dark\"");
        store.close();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "key", key.as_str()).unwrap();
        conn.execute_batch("DROP TRIGGER fail_backup_stage;")
            .unwrap();
        drop(conn);
        let store = Datastore::open_encrypted(path.to_string_lossy().into_owned(), key).unwrap();
        let context = store.get_sync_policy_context().unwrap().context_id;
        assert_eq!(
            store
                .stage_sync_backup_objects(context, vec![a, b], AT.into())
                .unwrap(),
            2
        );
        store.close();
        std::fs::remove_file(path).unwrap();
    }
}
