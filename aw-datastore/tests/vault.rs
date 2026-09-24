#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::Datastore;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn encrypted_creation_rejects_plaintext_and_wrong_key() {
    let path = std::env::temp_dir().join(format!("peak-vault-{}-{}.db", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    let key = "a".repeat(64);
    let datastore = Datastore::open_encrypted(path.to_string_lossy().into(), key.clone()).unwrap();
    datastore.force_commit().unwrap();
    datastore.close();
    assert!(!fs::read(&path).unwrap().starts_with(b"SQLite format 3"));
    let result = Datastore::open_encrypted(path.to_string_lossy().into(), "b".repeat(64));
    assert!(result.is_err());
    assert!(!format!("{result:?}").contains(&key));
    assert!(rusqlite::Connection::open(&path).unwrap()
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0)).is_err());
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
    let path = std::env::temp_dir().join(format!("peak-plaintext-{}-{}.db", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE example (value TEXT); INSERT INTO example VALUES ('synthetic');").unwrap();
    }
    let before = fs::read(&path).unwrap();
    assert!(Datastore::open_encrypted(path.to_string_lossy().into(), "c".repeat(64)).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
    fs::remove_file(path).unwrap();
}
