use aw_datastore::{Datastore, DatastoreError};

#[test]
fn closing_one_handle_locks_every_clone() {
    let store = Datastore::new_in_memory(false);
    let reader = store.clone();
    store.enable_capture_policy().unwrap();
    assert!(reader.get_buckets().is_ok());
    store.lock().unwrap();
    assert!(reader.is_locked());
    assert!(matches!(reader.get_buckets(), Err(DatastoreError::Locked)));
    assert!(store.lock().is_ok());
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[test]
fn encrypted_copy_preserves_source_and_requires_the_new_key() {
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};
    let root = std::env::temp_dir().join(format!("peak-copy-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&root).unwrap();
    let source = root.join("source.db");
    let backup = root.join("backup.db");
    let old_key = "a".repeat(64);
    let new_key = "b".repeat(64);
    let store = Datastore::open_encrypted(source.to_string_lossy().into(), old_key.clone()).unwrap();
    store.enable_capture_policy().unwrap();
    store.close();
    let before = fs::read(&source).unwrap();
    aw_datastore::vault::encrypted_copy(&source, Some(&old_key), &backup, &new_key).unwrap();
    assert_eq!(before, fs::read(&source).unwrap());
    assert!(aw_datastore::vault::verify(&backup, &new_key).is_ok());
    assert!(aw_datastore::vault::verify(&backup, &old_key).is_err());
    assert!(aw_datastore::vault::encrypted_copy(&source, Some(&old_key), &backup, &new_key).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[test]
fn plaintext_migration_requires_a_copy_and_replaces_only_with_verified_ciphertext() {
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};
    let root = std::env::temp_dir().join(format!("peak-migrate-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&root).unwrap();
    let source = root.join("sqlite.db");
    {
        let connection = rusqlite::Connection::open(&source).unwrap();
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE buckets (id TEXT PRIMARY KEY);
             CREATE TABLE events (id INTEGER PRIMARY KEY);
             INSERT INTO buckets VALUES ('local');
             INSERT INTO events VALUES (1), (2);"
        ).unwrap();
    }
    let before = aw_datastore::vault::preview_plaintext(&source).unwrap();
    assert_eq!(before, aw_datastore::vault::VaultFilePreview { buckets: 1, events: 2 });

    let key = "d".repeat(64);
    let after = aw_datastore::vault::migrate_plaintext(&source, &key).unwrap();
    assert_eq!(after, before);
    assert!(!fs::read(&source).unwrap().starts_with(b"SQLite format 3"));
    assert!(aw_datastore::vault::verify(&source, &key).is_ok());
    assert!(aw_datastore::vault::verify(&source, &"e".repeat(64)).is_err());
    fs::remove_dir_all(root).unwrap();
}
