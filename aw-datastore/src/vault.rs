//! SQLCipher file operations; legacy sources are replaced only after a verified copy.
use rusqlite::{params, Connection, DatabaseName, OpenFlags};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    if path.is_symlink() || !path.is_file() {
        return Err("Choose a regular database file".into());
    }
    let connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(error)?;
    let cipher: String = connection
        .pragma_query_value(None, "cipher_version", |row| row.get(0))
        .map_err(error)?;
    if cipher.is_empty() {
        return Err("SQLCipher support is required".into());
    }
    if let Some(key) = key {
        valid_key(key)?;
        connection.pragma_update(None, "key", key).map_err(error)?;
    }
    let integrity: String = connection
        .pragma_query_value(None, "integrity_check", |row| row.get(0))
        .map_err(error)?;
    if integrity != "ok" {
        return Err("Database integrity could not be verified".into());
    }
    let tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('buckets','events')",
        [], |row| row.get(0),
    ).map_err(error)?;
    if tables != 2 {
        return Err("This is not a supported PeakActivity/ActivityWatch Rust database; use a JSON export for other formats".into());
    }
    Ok(connection)
}

pub fn verify(path: &Path, key: &str) -> Result<(), String> {
    open_source(path, Some(key)).map(|_| ())
}

/// Reads continuity metadata without migrating or writing the original vault.
pub fn export_backup_deletions(
    path: &Path,
    key: &str,
) -> Result<Vec<aw_models::SnapshotDeletionFactV1>, String> {
    let connection = open_source(path, Some(key))?;
    connection.execute_batch("BEGIN").map_err(error)?;
    let version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(error)?;
    let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('sync_backup_deletions','sync_backup_deleted_objects')", [], |row| row.get(0)).map_err(error)?;
    if (0..15).contains(&version) && tables == 0 {
        return Ok(Vec::new());
    }
    if tables != 2 {
        return Err(
            "Backup deletion history could not be verified; source files were preserved".into(),
        );
    }
    let store = crate::DatastoreInstance::new_readonly_backup_ledger(&connection)
        .map_err(|_| "Backup deletion history is incompatible; source files were preserved")?;
    let context: String = store
        .policy_context
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    store
        .export_sync_backup_deletions(&connection, &context)
        .map_err(|_| {
            "Backup deletion history is invalid or too large; source files were preserved".into()
        })
}

/// Captures local retry provenance alongside facts without mutating the original database.
pub fn export_backup_continuity(path:&Path,key:&str)->Result<crate::SyncBackupContinuityV1,String>{
    let connection=open_source(path,Some(key))?;connection.execute_batch("BEGIN").map_err(error)?;
    let version:i32=connection.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(error)?;
    if version<15 {return export_backup_deletions(path,key).map(|facts|crate::SyncBackupContinuityV1{facts,records:Vec::new()});}
    let store=crate::DatastoreInstance::new_readonly_backup_ledger(&connection).map_err(|_|"Protected backup source is incompatible".to_string())?;
    let context=store.policy_context.iter().map(|b|format!("{b:02x}")).collect::<String>();
    store.export_sync_backup_continuity(&connection,&context).map_err(|_|"Protected backup source continuity is invalid".to_string())
}

pub fn preview_plaintext(path: &Path) -> Result<VaultFilePreview, String> {
    let connection = open_source(path, None)?;
    let buckets: i64 = connection
        .query_row("SELECT count(*) FROM buckets", [], |row| row.get(0))
        .map_err(error)?;
    let events: i64 = connection
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .map_err(error)?;
    Ok(VaultFilePreview {
        buckets: buckets as u64,
        events: events as u64,
    })
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

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?
        .as_nanos();
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
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(error)?;
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
pub fn encrypted_copy(
    source: &Path,
    source_key: Option<&str>,
    destination: &Path,
    destination_key: &str,
) -> Result<(), String> {
    valid_key(destination_key)?;
    if destination.exists() || destination.is_symlink() {
        return Err("The destination must not already exist".into());
    }
    drop(open_source(source, source_key)?);
    let absolute = fs::canonicalize(source).map_err(error)?;
    let path = absolute
        .to_str()
        .ok_or("Database path is not valid UTF-8")?;
    let mut source_uri = String::from("file:");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            source_uri.push(byte as char);
        } else {
            source_uri.push_str(&format!("%{byte:02X}"));
        }
    }
    source_uri.push_str("?mode=ro");
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(destination)
        .map_err(error)?
        .sync_all()
        .map_err(error)?;
    let result = (|| {
        let copy = Connection::open_with_flags(
            destination,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(error)?;
        copy.pragma_update(None, "key", destination_key)
            .map_err(error)?;
        copy.execute(
            "ATTACH DATABASE ?1 AS source KEY ?2",
            params![source_uri, source_key.unwrap_or("")],
        )
        .map_err(error)?;
        copy.execute_batch("BEGIN").map_err(error)?;
        let integrity: String = copy
            .pragma_query_value(
                Some(DatabaseName::Attached("source")),
                "integrity_check",
                |row| row.get(0),
            )
            .map_err(error)?;
        if integrity != "ok" {
            return Err("Database integrity could not be verified".into());
        }
        let version: i64 = copy
            .pragma_query_value(
                Some(DatabaseName::Attached("source")),
                "user_version",
                |row| row.get(0),
            )
            .map_err(error)?;
        let events: i64 = copy
            .query_row("SELECT count(*) FROM source.events", [], |row| row.get(0))
            .map_err(error)?;
        // The writable destination owns the connection; the source remains read-only.
        copy.query_row("SELECT sqlcipher_export('main', 'source')", [], |_| Ok(()))
            .map_err(error)?;
        copy.pragma_update(None, "user_version", version)
            .map_err(error)?;
        copy.execute_batch("COMMIT; DETACH DATABASE source")
            .map_err(error)?;
        drop(copy);
        let copy = open_source(destination, Some(destination_key))?;
        let copied_events: i64 = copy
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .map_err(error)?;
        if copied_events != events {
            return Err(
                "Source changed during export; stop recording in its application and retry".into(),
            );
        }
        drop(copy);
        fs::File::open(destination)
            .map_err(error)?
            .sync_all()
            .map_err(error)?;
        Ok(())
    })();
    // A failed destination is kept for inspection; it never replaces the active vault.
    result
}
