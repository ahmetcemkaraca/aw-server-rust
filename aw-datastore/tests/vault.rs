#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::Datastore;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn encrypted_copy_preserves_source_and_reencrypts_complete_vault() {
    let root = std::env::temp_dir().join(format!(
        "peak-encrypted-copy-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let source = root.join("source %?# café.db");
    let destination = root.join("destination.db");
    let source_key = "a".repeat(64);
    let destination_key = "b".repeat(64);
    let datastore =
        Datastore::open_encrypted(source.to_string_lossy().into_owned(), source_key.clone())
            .unwrap();
    datastore
        .set_key_value("copy-test-value", "synthetic private copy marker")
        .unwrap();
    datastore
        .create_sync_device_identity(&aw_datastore::SyncDeviceIdentity::new(
            [0x21; 16],
            zeroize::Zeroizing::new([0x31; 32]),
            zeroize::Zeroizing::new([0x41; 32]),
        ))
        .unwrap();
    let bucket = aw_models::Bucket {
        bid: None,
        id: "aw-watcher-window_copy-test".into(),
        _type: "currentwindow".into(),
        client: "copy-test".into(),
        hostname: "synthetic".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: None,
        last_updated: None,
    };
    datastore.create_bucket(&bucket).unwrap();
    datastore
        .insert_events(
            &bucket.id,
            &[aw_models::Event::new(
                chrono::Utc::now(),
                chrono::Duration::seconds(3),
                serde_json::json!({"app":"synthetic","title":"synthetic private activity marker"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )],
        )
        .unwrap();
    datastore.close();
    let before = fs::read(&source).unwrap();
    aw_datastore::vault::encrypted_copy(&source, Some(&source_key), &destination, &destination_key)
        .unwrap();
    assert!(
        fs::read(&source).unwrap() == before,
        "copy must not change source ciphertext"
    );
    aw_datastore::vault::verify(&source, &source_key).unwrap();
    aw_datastore::vault::verify(&destination, &destination_key).unwrap();
    assert!(aw_datastore::vault::verify(&destination, &source_key).is_err());
    let copy =
        Datastore::open_encrypted(destination.to_string_lossy().into_owned(), destination_key)
            .unwrap();
    assert_eq!(
        copy.get_key_value("copy-test-value").unwrap(),
        "synthetic private copy marker"
    );
    assert_eq!(
        copy.load_sync_device_identity()
            .unwrap()
            .unwrap()
            .device_id(),
        &[0x21; 16]
    );
    let events = copy.get_events(&bucket.id, None, None, None).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].duration, chrono::Duration::seconds(3));
    copy.close();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn encrypted_creation_rejects_plaintext_and_wrong_key() {
    let path = std::env::temp_dir().join(format!(
        "peak-vault-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let key = "a".repeat(64);
    let datastore = Datastore::open_encrypted(path.to_string_lossy().into(), key.clone()).unwrap();
    datastore.force_commit().unwrap();
    datastore.close();
    assert!(!fs::read(&path).unwrap().starts_with(b"SQLite format 3"));
    let result = Datastore::open_encrypted(path.to_string_lossy().into(), "b".repeat(64));
    assert!(result.is_err());
    assert!(!format!("{result:?}").contains(&key));
    assert!(rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row
            .get::<_, i64>(0))
        .is_err());
    let _ = fs::remove_file(path);
}

#[test]
fn absent_key_cannot_create_a_database() {
    let path = std::env::temp_dir().join(format!("peak-missing-key-{}.db", std::process::id()));
    assert!(Datastore::open_encrypted(path.to_string_lossy().into(), String::new()).is_err());
    assert!(!path.exists());
}

#[test]
fn plaintext_database_is_preserved_for_explicit_migration() {
    let path = std::env::temp_dir().join(format!(
        "peak-plaintext-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE example (value TEXT); INSERT INTO example VALUES ('synthetic');",
        )
        .unwrap();
    }
    let before = fs::read(&path).unwrap();
    assert!(Datastore::open_encrypted(path.to_string_lossy().into(), "c".repeat(64)).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
    fs::remove_file(path).unwrap();
}

#[test]
fn readonly_backup_deletion_export_preserves_ciphertext_and_refuses_corruption() {
    use aw_sync_e2ee::{
        create_vault_data_key, encrypt_snapshot, generate_account_root_key, SnapshotDeletionProofV1,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let root = std::env::temp_dir().join(format!(
        "peak-readonly-deletions-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("source.db");
    let secret = "a".repeat(64);
    let store =
        Datastore::open_encrypted(path.to_string_lossy().into_owned(), secret.clone()).unwrap();
    let key = create_vault_data_key(
        &generate_account_root_key().unwrap(),
        &URL_SAFE_NO_PAD.encode([0x71; 16]),
        1,
    )
    .unwrap()
    .0;
    let snapshot = encrypt_snapshot(&key, b"known deleted version").unwrap();
    let fact = SnapshotDeletionProofV1::authenticate(&key, &snapshot)
        .unwrap()
        .fact()
        .clone();
    store
        .merge_sync_backup_deletions(
            store.get_sync_policy_context().unwrap().context_id,
            vec![fact.clone()],
            "2026-10-14T12:00:00Z".into(),
        )
        .unwrap();
    store.close();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        aw_datastore::vault::export_backup_deletions(&path, &secret).unwrap(),
        vec![fact.clone()]
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    let schema15=rusqlite::Connection::open(&path).unwrap();
    schema15.pragma_update(None,"key",&secret).unwrap();
    schema15.execute_batch("ALTER TABLE sync_backup_deletions DROP COLUMN sealed_record_json; PRAGMA user_version=15;").unwrap();
    drop(schema15);
    let before15=fs::read(&path).unwrap();
    assert_eq!(aw_datastore::vault::export_backup_deletions(&path,&secret).unwrap(),vec![fact]);
    assert_eq!(fs::read(&path).unwrap(),before15);
    assert!(aw_datastore::vault::export_backup_deletions(&path, &"b".repeat(64)).is_err());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "key", &secret).unwrap();
    conn.execute("DELETE FROM sync_backup_deleted_objects", [])
        .unwrap();
    drop(conn);
    let corrupt = fs::read(&path).unwrap();
    assert!(aw_datastore::vault::export_backup_deletions(&path, &secret).is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupt);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn readonly_backup_deletion_export_accepts_verified_legacy_without_migrating_it() {
    let path = std::env::temp_dir().join(format!(
        "peak-readonly-legacy-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let secret = "a".repeat(64);
    Datastore::open_encrypted(path.to_string_lossy().into_owned(), secret.clone())
        .unwrap()
        .close();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "key", &secret).unwrap();
    conn.execute_batch("DROP TABLE sync_backup_deleted_objects; DROP TABLE sync_backup_deletions; PRAGMA user_version=14;").unwrap();
    drop(conn);
    let before = fs::read(&path).unwrap();
    assert!(aw_datastore::vault::export_backup_deletions(&path, &secret)
        .unwrap()
        .is_empty());
    assert_eq!(fs::read(&path).unwrap(), before);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "key", &secret).unwrap();
    conn.pragma_update(None, "user_version", 15).unwrap();
    drop(conn);
    assert!(aw_datastore::vault::export_backup_deletions(&path, &secret).is_err());
    fs::remove_file(path).unwrap();
}
