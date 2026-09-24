//! SQLCipher file operations; legacy sources are replaced only after a verified copy.
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use rusqlite::{Connection, DatabaseName, OpenFlags, params};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultFilePreview {
    pub buckets: u64,
    pub events: u64,
}

fn error(_: impl std::fmt::Display) -> String {
    "Vault file operation failed; source files were preserved".into()
}

fn valid_key(key: &str) -> Result<(), String> {
    if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("A 64-character recovery key is required".into());
    }
    Ok(())
}

fn open_source(path: &Path, key: Option<&str>) -> Result<Connection, String> {
    if path.is_symlink() || !path.is_file() { return Err("Choose a regular database file".into()); }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(error)?;
    let cipher: String = connection.pragma_query_value(None, "cipher_version", |row| row.get(0)).map_err(error)?;
    if cipher.is_empty() { return Err("SQLCipher support is required".into()); }
    if let Some(key) = key {
        valid_key(key)?;
        connection.pragma_update(None, "key", key).map_err(error)?;
    }
    let integrity: String = connection.pragma_query_value(None, "integrity_check", |row| row.get(0)).map_err(error)?;
    if integrity != "ok" { return Err("Database integrity could not be verified".into()); }
    let tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('buckets','events')",
        [], |row| row.get(0),
    ).map_err(error)?;
    if tables != 2 { return Err("This is not a supported PeakActivity/ActivityWatch Rust database; use a JSON export for other formats".into()); }
    Ok(connection)
}

pub fn verify(path: &Path, key: &str) -> Result<(), String> {
    open_source(path, Some(key)).map(|_| ())
}

pub fn preview_plaintext(path: &Path) -> Result<VaultFilePreview, String> {
    let connection = open_source(path, None)?;
    let buckets: i64 = connection.query_row("SELECT count(*) FROM buckets", [], |row| row.get(0)).map_err(error)?;
    let events: i64 = connection.query_row("SELECT count(*) FROM events", [], |row| row.get(0)).map_err(error)?;
    Ok(VaultFilePreview { buckets: buckets as u64, events: events as u64 })
}

/// Replaces a validated plaintext database only after a complete encrypted copy exists.
pub fn migrate_plaintext(path: &Path, key: &str) -> Result<VaultFilePreview, String> {
    valid_key(key)?;
    let before_checkpoint = preview_plaintext(path)?;
    checkpoint(path)?;
    let preview = preview_plaintext(path)?;
    if preview != before_checkpoint {
        return Err("Source changed during vault migration; stop recording and retry".into());
    }

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(error)?.as_nanos();
    let filename = path.file_name().ok_or("Database path has no filename")?;
    let mut staged_name = OsString::from(".");
    staged_name.push(filename);
    staged_name.push(format!(".encrypted-{}-{stamp}.tmp", std::process::id()));
    let staged = path.with_file_name(staged_name);
    encrypted_copy(path, None, &staged, key)?;
    if preview_plaintext(path)? != preview {
        return Err("Source changed during vault migration; stop recording and retry".into());
    }

    for suffix in ["-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        if sidecar.is_symlink() {
            return Err("Database sidecar is not a regular file".into());
        }
        if sidecar.exists() {
            fs::remove_file(sidecar).map_err(error)?;
        }
    }
    fs::rename(&staged, path).map_err(error)?;
    if let Some(parent) = path.parent() {
        File::open(parent).and_then(|directory| directory.sync_all()).map_err(error)?;
    }
    verify(path, key)?;
    Ok(preview)
}

fn checkpoint(path: &Path) -> Result<(), String> {
    let connection = Connection::open(path).map_err(error)?;
    let (busy, log, checkpointed): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(error)?;
    if busy != 0 || (log >= 0 && log != checkpointed) {
        return Err("Database is busy; stop recording and retry the migration".into());
    }
    Ok(())
}

/// Used for migration, encrypted backups, restore and copy-on-write key rotation.
pub fn encrypted_copy(source: &Path, source_key: Option<&str>, destination: &Path, destination_key: &str) -> Result<(), String> {
    valid_key(destination_key)?;
    if destination.exists() || destination.is_symlink() { return Err("The destination must not already exist".into()); }
    let source = open_source(source, source_key)?;
    source.execute_batch("BEGIN").map_err(error)?;
    let version: i64 = source.pragma_query_value(None, "user_version", |row| row.get(0)).map_err(error)?;
    let events: i64 = source.query_row("SELECT count(*) FROM events", [], |row| row.get(0)).map_err(error)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    options.open(destination).map_err(error)?.sync_all().map_err(error)?;
    let result = (|| {
        let path = destination.to_str().ok_or("Database path is not valid UTF-8")?;
        source.execute("ATTACH DATABASE ?1 AS destination KEY ?2", params![path, destination_key]).map_err(error)?;
        source.query_row("SELECT sqlcipher_export('destination')", [], |_| Ok(())).map_err(error)?;
        source.pragma_update(Some(DatabaseName::Attached("destination")), "user_version", version).map_err(error)?;
        source.execute_batch("COMMIT; DETACH DATABASE destination").map_err(error)?;
        let copy = open_source(destination, Some(destination_key))?;
        let copied_events: i64 = copy.query_row("SELECT count(*) FROM events", [], |row| row.get(0)).map_err(error)?;
        if copied_events != events { return Err("Source changed during export; stop recording in its application and retry".into()); }
        drop(copy);
        fs::File::open(destination).map_err(error)?.sync_all().map_err(error)?;
        Ok(())
    })();
    // A failed destination is kept for inspection; it never replaces the active vault.
    result
}
