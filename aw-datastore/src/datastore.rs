use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use base64::Engine;

use rusqlite::{Connection, OptionalExtension};

use serde_json::value::Value;

use aw_models::{Bucket, DevicePublicIdentityV1};
use aw_models::BucketMetadata;
use aw_models::{
    EgressApprovalScopeV1, EgressApprovalV1, EgressPolicyV1, EgressReceiptV1, EgressUserPolicyV1, Event,
    validate_plugin_write_intent_v1, PluginManifestV1,
    PluginOwnedEventV1, PluginStorageIntentV1, PluginWriteIntentV1,
    SignedEgressPolicyBundleV1, SyncBucketDescriptorV1, SyncOperationKindV1,
    PLUGIN_MAX_GRANTS_V1, PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1, PLUGIN_MAX_PLUGIN_EVENT_BYTES_V1,
    PLUGIN_MAX_STORAGE_BYTES_V1,
};

use rusqlite::params;
use rusqlite::types::ToSql;
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

use super::DatastoreError;
use crate::EgressSecrets;
pub(crate) const AI_SETTINGS_KEY: &str = "settings.ai.v1";
pub(crate) const AI_HISTORY_KEY: &str = "settings.ai.history.v1";
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use crate::SyncDeviceIdentity;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_models::SYNC_MAX_CHUNK_BYTES;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use crate::{
    SyncApplyBatchV1, SyncBaselineProgressV1, SyncDeviceAccessEvent, SyncHeadCommitV1,
    SyncManifestHeadV1, SyncRecoveryBucketMappingV1, SyncRecoveryCounterV1,
    SyncRecoveryEventMappingV1, SyncRecoveryStateV1, SyncRecoveryStreamHeadV1,
    SyncRecoveryTombstoneAckV1, SyncRecoveryTrustedDeviceV1, SyncStoredOperationV1,
    SyncTrustedDevice,
};
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_sync_e2ee::{
    create_event_correction, create_event_tombstone, create_event_upsert,
    decode_sync_data_field_v1, encode_sync_data_field_v1, merge_operations,
    ManifestDecisionV1, SyncHeadV1, SyncOperationV1,
};

fn _get_db_version(conn: &Connection) -> i32 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

fn with_savepoint<T>(
    conn: &Connection,
    name: &str,
    operation: impl FnOnce() -> Result<T, DatastoreError>,
) -> Result<T, DatastoreError> {
    conn.execute_batch(&format!("SAVEPOINT {name}"))
        .map_err(|_| DatastoreError::InternalError("Could not begin datastore operation".into()))?;
    let rollback = || {
        conn.execute_batch(&format!("ROLLBACK TO SAVEPOINT {name}; RELEASE SAVEPOINT {name}")).is_ok()
    };
    match operation() {
        Ok(value) if conn.execute_batch(&format!("RELEASE SAVEPOINT {name}")).is_ok() => Ok(value),
        Ok(_) => {
            if !rollback() { let _ = conn.execute_batch("ROLLBACK"); }
            Err(DatastoreError::InternalError("Could not finish datastore operation".into()))
        }
        Err(error) => {
            if rollback() { Err(error) }
            else {
                let _ = conn.execute_batch("ROLLBACK");
                Err(DatastoreError::InternalError("Datastore operation failed and rollback could not be confirmed".into()))
            }
        }
    }
}

fn decode_egress_approval(
    id: String,
    destination_id: String,
    purpose_id: String,
    retention_id: String,
    version: i64,
    scope: String,
    expires_at: Option<String>,
    created_at: String,
) -> Result<EgressApprovalV1, DatastoreError> {
    let invalid = || DatastoreError::InternalError("Stored egress approval is invalid".into());
    let expires_at = expires_at.map(|value| DateTime::parse_from_rfc3339(&value).map(|date| date.with_timezone(&Utc)))
        .transpose().map_err(|_| invalid())?;
    let created_at = DateTime::parse_from_rfc3339(&created_at)
        .map(|date| date.with_timezone(&Utc)).map_err(|_| invalid())?;
    Ok(EgressApprovalV1 {
        schema_version: 1,
        approval_id: id,
        destination_id,
        purpose_id,
        retention_id,
        policy_version: u64::try_from(version).map_err(|_| invalid())?,
        scope: serde_json::from_str(&scope).map_err(|_| invalid())?,
        expires_at,
        created_at,
    })
}

fn decode_secret(value: &str) -> Result<[u8; 32], DatastoreError> {
    if value.len() != 64 {
        return Err(DatastoreError::InternalError("Stored local privacy key is invalid".into()));
    }
    let mut secret = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)
            .ok_or_else(|| DatastoreError::InternalError("Stored local privacy key is invalid".into()))?;
        let low = (pair[1] as char).to_digit(16)
            .ok_or_else(|| DatastoreError::InternalError("Stored local privacy key is invalid".into()))?;
        secret[index] = ((high << 4) | low) as u8;
    }
    Ok(secret)
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
fn validate_sync_id(value: &str) -> Result<(), DatastoreError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DatastoreError::InternalError("Invalid opaque sync object ID".into()))?;
    if bytes.len() != 16 {
        return Err(DatastoreError::InternalError("Invalid opaque sync object ID".into()));
    }
    Ok(())
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_egress_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')))
        })
}

fn empty_egress_user_policy() -> EgressUserPolicyV1 {
    EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: Vec::new(),
        safe_zone_patterns: Vec::new(),
        after_hours: None,
    }
}

fn validate_egress_user_policy(user: &EgressUserPolicyV1) -> Result<(), DatastoreError> {
    user.validate()
        .map_err(|_| DatastoreError::InternalError("Invalid egress user policy".into()))
}

/*
 * ### Database version changelog ###
 * 0: Uninitialized database
 * 1: Initialized database
 * 2: Added 'data' field to 'buckets' table
 * 3: see: https://github.com/ActivityWatch/aw-server-rust/pull/52
 * 4: Added 'key_value' table for storing key - value pairs
 * 5: Replaced single-column events indexes with a composite index
 * 6: Added metadata-only event correction provenance
 * 7: Added content-free outbound egress receipts
 * 8: Added scoped outbound egress approvals
 * 9: Added private local sync device identity storage
 * 10: Added signed device identities, bucket/event mappings and per-device sync streams
 * 11: Added encrypted plugin-owned storage
 * 12: Added schema-checked plugin-owned annotation events
 */
static NEWEST_DB_VERSION: i32 = 12;
const EGRESS_KILL_SWITCH_KEY: &str = "egress.kill_switch";
const EGRESS_ALIAS_SECRET_KEY: &str = "egress.alias_secret";
const EGRESS_APPROVAL_SECRET_KEY: &str = "egress.approval_secret";
const EGRESS_POLICY_STATE_KEY: &str = "egress.policy_state";
const EGRESS_USER_POLICY_KEY: &str = "egress.user_policy";
const EGRESS_APPROVAL_MAX_SECONDS: i64 = 30 * 24 * 60 * 60;
const EGRESS_ONCE_MAX_SECONDS: i64 = 10 * 60;

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredEgressPolicyState {
    bundle: SignedEgressPolicyBundleV1,
    user_policy: EgressUserPolicyV1,
}

fn _create_tables(conn: &Connection, version: i32, encrypted: bool) -> bool {
    let mut first_init = false;

    if version < 1 {
        first_init = true;
        _migrate_v0_to_v1(conn);
    }

    if version < 2 {
        _migrate_v1_to_v2(conn);
    }

    if version < 3 {
        _migrate_v2_to_v3(conn);
    }

    if version < 4 {
        _migrate_v3_to_v4(conn);
    }

    if version < 5 {
        _migrate_v4_to_v5(conn);
    }

    if version < 6 {
        _migrate_v5_to_v6(conn);
    }

    if version < 7 {
        _migrate_v6_to_v7(conn);
    }

    if version < 8 {
        _migrate_v7_to_v8(conn);
    }

    if version < 9 {
        _migrate_v8_to_v9(conn);
    }

    if version < 10 {
        _migrate_v9_to_v10(conn, encrypted);
    }

    if version < 11 {
        _migrate_v10_to_v11(conn);
    }

    if version < 12 {
        _migrate_v11_to_v12(conn);
    }

    first_init
}

fn _migrate_v0_to_v1(conn: &Connection) {
    /* Set up bucket table */
    conn.execute(
        "
        CREATE TABLE IF NOT EXISTS buckets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            client TEXT NOT NULL,
            hostname TEXT NOT NULL,
            created TEXT NOT NULL
        )",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to create buckets table");

    /* Set up index for bucket table */
    conn.execute(
        "CREATE INDEX IF NOT EXISTS bucket_id_index ON buckets(id)",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to create buckets index");

    /* Set up events table */
    conn.execute(
        "
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bucketrow INTEGER NOT NULL,
            starttime INTEGER NOT NULL,
            endtime INTEGER NOT NULL,
            data TEXT NOT NULL,
            FOREIGN KEY (bucketrow) REFERENCES buckets(id)
        )",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to create events table");

    /* Set up index for events table */
    conn.execute(
        "CREATE INDEX IF NOT EXISTS events_bucketrow_index ON events(bucketrow)",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to create events_bucketrow index");
    conn.execute(
        "CREATE INDEX IF NOT EXISTS events_starttime_index ON events(starttime)",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to create events_starttime index");
    conn.execute(
        "CREATE INDEX IF NOT EXISTS events_endtime_index ON events(endtime)",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to create events_endtime index");

    /* Update database version */
    conn.pragma_update(None, "user_version", 1)
        .expect("Failed to update database version!");
}

fn _migrate_v1_to_v2(conn: &Connection) {
    info!("Upgrading database to v2, adding data field to buckets");
    conn.execute(
        "ALTER TABLE buckets ADD COLUMN data TEXT DEFAULT '{}';",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to upgrade database when adding data field to buckets");

    conn.pragma_update(None, "user_version", 2)
        .expect("Failed to update database version!");
}

fn _migrate_v2_to_v3(conn: &Connection) {
    // For details about why this migration was necessary, see: https://github.com/ActivityWatch/aw-server-rust/pull/52
    info!("Upgrading database to v3, replacing the broken data field for buckets");

    // Rename column, marking it as deprecated
    match conn.execute(
        "ALTER TABLE buckets RENAME COLUMN data TO data_deprecated;",
        &[] as &[&dyn ToSql],
    ) {
        Ok(_) => (),
        // This error is okay, it still has the intended effects
        Err(rusqlite::Error::ExecuteReturnedResults) => (),
        Err(e) => panic!("Unexpected error: {e:?}"),
    };

    // Create new correct column
    conn.execute(
        "ALTER TABLE buckets ADD COLUMN data TEXT NOT NULL DEFAULT '{}';",
        &[] as &[&dyn ToSql],
    )
    .expect("Failed to upgrade database when adding new data field to buckets");

    conn.pragma_update(None, "user_version", 3)
        .expect("Failed to update database version!");
}

fn _migrate_v3_to_v4(conn: &Connection) {
    info!("Upgrading database to v4, adding table for key-value storage");
    conn.execute(
        "CREATE TABLE key_value (
        key TEXT PRIMARY KEY,
        value TEXT,
        last_modified NUMBER NOT NULL
    );",
        [],
    )
    .expect("Failed to upgrade db and add key-value storage table");

    conn.pragma_update(None, "user_version", 4)
        .expect("Failed to update database version!");
}

fn _migrate_v4_to_v5(conn: &Connection) {
    info!(
        "Upgrading database to v5, replacing single-column events indexes with a composite index"
    );
    // Every event query filters on bucketrow and a starttime/endtime range,
    // ordered by starttime. A composite index serves the seek, the range scan
    // and the ORDER BY in one pass (with endtime checked from the index
    // without fetching the row), where the single-column indexes could only
    // cover one predicate and left the rest as scan + sort. Dropping them
    // also makes inserts cheaper (one index to maintain instead of three).
    //
    // starttime is DESC so a forward scan yields the query's newest-first
    // order with equal-timestamp events in rowid (insertion) order, matching
    // the ordering callers observed before this index existed.
    //
    // The drops run before the create so the pages they free are reused to
    // build the new index within the same transaction; creating first would
    // permanently grow the database file by the new index's size.
    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        DROP INDEX IF EXISTS events_bucketrow_index;
        DROP INDEX IF EXISTS events_starttime_index;
        DROP INDEX IF EXISTS events_endtime_index;
        CREATE INDEX IF NOT EXISTS events_bucketrow_starttime_endtime_index
            ON events(bucketrow, starttime DESC, endtime);
        PRAGMA user_version = 5;
        COMMIT;
    ",
    )
    .expect("Failed to run v5 migration transaction");
}

fn _migrate_v5_to_v6(conn: &Connection) {
    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        CREATE TABLE event_corrections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bucketrow INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            corrected_at TEXT NOT NULL,
            source TEXT NOT NULL,
            fields TEXT NOT NULL,
            FOREIGN KEY (bucketrow) REFERENCES buckets(id)
        );
        CREATE INDEX event_corrections_lookup_index
            ON event_corrections(bucketrow, event_id, id);
        PRAGMA user_version = 6;
        COMMIT;
        ",
    )
    .expect("Failed to run v6 correction-provenance migration");
}

fn _migrate_v6_to_v7(conn: &Connection) {
    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        CREATE TABLE egress_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            destination_id TEXT NOT NULL,
            purpose_id TEXT NOT NULL,
            retention_id TEXT NOT NULL,
            allowed_fields TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            scope TEXT NOT NULL,
            decision TEXT NOT NULL
        );
        CREATE INDEX egress_receipts_created_index
            ON egress_receipts(created_at DESC, id DESC);
        PRAGMA user_version = 7;
        COMMIT;
        ",
    )
    .expect("Failed to run v7 content-free egress receipt migration");
}

fn _migrate_v7_to_v8(conn: &Connection) {
    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        CREATE TABLE egress_approvals (
            id TEXT PRIMARY KEY,
            destination_id TEXT NOT NULL,
            purpose_id TEXT NOT NULL,
            retention_id TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            scope TEXT NOT NULL,
            payload_tag BLOB NOT NULL,
            expires_at TEXT,
            uses_remaining INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX egress_approvals_expiry_index ON egress_approvals(expires_at);
        PRAGMA user_version = 8;
        COMMIT;
        ",
    )
    .expect("Failed to run v8 scoped egress approval migration");
}

fn _migrate_v8_to_v9(conn: &Connection) {
    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        CREATE TABLE sync_device_identity (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            device_id BLOB NOT NULL CHECK(length(device_id) = 16),
            private_key BLOB NOT NULL CHECK(length(private_key) = 32)
        );
        CREATE TABLE sync_key_material (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            account_root_key BLOB NOT NULL CHECK(length(account_root_key) = 32),
            vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
            wrapped_nonce BLOB NOT NULL CHECK(length(wrapped_nonce) = 24),
            wrapped_ciphertext BLOB NOT NULL CHECK(length(wrapped_ciphertext) = 48)
        );
        CREATE TABLE sync_trusted_devices (
            device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
            x25519_public_key BLOB NOT NULL CHECK(length(x25519_public_key) = 32),
            paired_at TEXT NOT NULL,
            revoked_at TEXT,
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0)
        );
        CREATE TABLE sync_device_access_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id BLOB NOT NULL CHECK(length(device_id) = 16),
            action TEXT NOT NULL CHECK(action IN ('paired', 'revoked')),
            occurred_at TEXT NOT NULL
        );
        CREATE TABLE sync_pairing_offers (
            offer_id BLOB PRIMARY KEY CHECK(length(offer_id) = 16),
            peer_device_id BLOB NOT NULL CHECK(length(peer_device_id) = 16),
            completed_at TEXT NOT NULL
        );
        CREATE TABLE sync_manifest_heads (
            vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 16),
            revision INTEGER NOT NULL CHECK(revision > 0),
            head_hash BLOB NOT NULL CHECK(length(head_hash) = 32)
        );
        CREATE TABLE sync_snapshot_current (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            snapshot_id BLOB NOT NULL UNIQUE CHECK(length(snapshot_id) = 16)
        );
        CREATE TABLE sync_snapshot_chunks (
            snapshot_id BLOB NOT NULL CHECK(length(snapshot_id) = 16),
            chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),
            object_id TEXT NOT NULL,
            vault_id TEXT NOT NULL,
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            PRIMARY KEY(snapshot_id, chunk_index),
            UNIQUE(object_id)
        );
        CREATE TABLE sync_objects (
            object_id TEXT PRIMARY KEY CHECK(length(object_id) = 22),
            vault_id TEXT NOT NULL CHECK(length(vault_id) = 22),
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
            nonce TEXT NOT NULL CHECK(length(nonce) = 32),
            ciphertext TEXT NOT NULL CHECK(length(ciphertext) <= 2796300),
            stored_at TEXT NOT NULL
        );
        CREATE INDEX sync_objects_vault_order_index
            ON sync_objects(vault_id, object_id);
        CREATE TABLE sync_object_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id TEXT NOT NULL CHECK(length(object_id) = 22),
            action TEXT NOT NULL CHECK(action IN ('stored', 'deleted')),
            occurred_at TEXT NOT NULL
        );
        CREATE INDEX sync_object_history_order_index ON sync_object_history(id DESC);
        CREATE TABLE sync_runtime_control (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
            destination_id TEXT,
            purpose_id TEXT
        );
        CREATE TABLE sync_device_counters (
            device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
            last_counter INTEGER NOT NULL CHECK(last_counter > 0)
        );
        CREATE TABLE sync_recovery_confirmation (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            confirmed_at TEXT NOT NULL
        );
        CREATE TABLE sync_tombstone_acknowledgements (
            origin_device_id BLOB NOT NULL CHECK(length(origin_device_id) = 16),
            local_event_id INTEGER NOT NULL CHECK(local_event_id > 0),
            tombstone_counter INTEGER NOT NULL CHECK(tombstone_counter > 0),
            device_id BLOB NOT NULL CHECK(length(device_id) = 16),
            acknowledged_at TEXT NOT NULL,
            PRIMARY KEY(origin_device_id, local_event_id, tombstone_counter, device_id)
        );
        CREATE INDEX sync_device_history_order_index
            ON sync_device_access_history(id DESC);
        PRAGMA user_version = 9;
        COMMIT;
        ",
    )
    .expect("Failed to run v9 encrypted sync-identity migration");
}

fn _migrate_v9_to_v10(conn: &Connection, encrypted: bool) {
    let has_local_identity = conn
        .query_row("SELECT 1 FROM sync_device_identity WHERE id = 1", [], |_| Ok(()))
        .optional()
        .expect("Failed to inspect the local sync identity before v10 migration")
        .is_some();
    let mut signing_seed = zeroize::Zeroizing::new([0u8; 32]);
    if has_local_identity && encrypted {
        SystemRandom::new()
            .fill(&mut signing_seed[..])
            .expect("Secure randomness is required to migrate the local sync identity");
    }

    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        ALTER TABLE sync_device_identity ADD COLUMN signing_seed BLOB
            CHECK(signing_seed IS NULL OR length(signing_seed) = 32);
        ALTER TABLE sync_trusted_devices ADD COLUMN ed25519_public_key BLOB
            CHECK(ed25519_public_key IS NULL OR length(ed25519_public_key) = 32);
        CREATE TABLE sync_bucket_mappings (
            sync_bucket_id BLOB PRIMARY KEY CHECK(length(sync_bucket_id) = 16),
            local_bucket_id TEXT NOT NULL UNIQUE,
            descriptor_json TEXT NOT NULL
        );
        CREATE TABLE sync_event_mappings (
            origin_device_id BLOB NOT NULL CHECK(length(origin_device_id) = 16),
            origin_event_id INTEGER NOT NULL CHECK(origin_event_id > 0),
            sync_bucket_id BLOB NOT NULL CHECK(length(sync_bucket_id) = 16),
            local_bucket_id TEXT NOT NULL,
            local_event_id INTEGER CHECK(local_event_id IS NULL OR local_event_id > 0),
            deleted INTEGER NOT NULL CHECK(deleted IN (0, 1)),
            PRIMARY KEY(origin_device_id, origin_event_id),
            UNIQUE(local_bucket_id, local_event_id)
        );
        CREATE TABLE sync_operations (
            device_id BLOB NOT NULL CHECK(length(device_id) = 16),
            counter INTEGER NOT NULL CHECK(counter > 0),
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
            operation_json TEXT NOT NULL,
            content_hash BLOB NOT NULL CHECK(length(content_hash) = 32),
            PRIMARY KEY(device_id, counter)
        );
        CREATE INDEX sync_operations_epoch_order_index
            ON sync_operations(key_epoch, device_id, counter);
        CREATE TABLE sync_stream_heads (
            vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
            device_id BLOB NOT NULL CHECK(length(device_id) = 16),
            revision INTEGER NOT NULL CHECK(revision > 0),
            head_hash BLOB NOT NULL CHECK(length(head_hash) = 32),
            PRIMARY KEY(vault_id, key_epoch, device_id)
        );
        CREATE TABLE sync_journal_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            active INTEGER NOT NULL CHECK(active IN (0, 1)),
            key_epoch INTEGER NOT NULL CHECK(key_epoch > 0),
            baseline_max_event_id INTEGER NOT NULL CHECK(baseline_max_event_id >= 0),
            baseline_cursor INTEGER NOT NULL CHECK(baseline_cursor >= 0),
            baseline_complete INTEGER NOT NULL CHECK(baseline_complete IN (0, 1))
        );
        UPDATE sync_runtime_control SET enabled = 0, destination_id = NULL, purpose_id = NULL;
        ",
    )
    .expect("Failed to add v10 sync mapping and stream tables");

    if has_local_identity && encrypted {
        conn.execute(
            "UPDATE sync_device_identity SET signing_seed = ?1 WHERE id = 1",
            [&signing_seed[..]],
        )
        .expect("Failed to initialize the local Ed25519 signing seed");
    }
    conn.execute_batch("PRAGMA user_version = 10; COMMIT;")
        .expect("Failed to commit v10 sync mapping and stream migration");
}

fn _migrate_v10_to_v11(conn: &Connection) {
    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        CREATE TABLE plugin_storage (
            publisher_key_id TEXT NOT NULL,
            plugin_id TEXT NOT NULL,
            storage_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            PRIMARY KEY(publisher_key_id, plugin_id, storage_key)
        );
        PRAGMA user_version = 11;
        COMMIT;
        ",
    ).expect("Failed to add encrypted plugin storage");
}

fn _migrate_v11_to_v12(conn: &Connection) {
    conn.execute_batch(
        "
        BEGIN EXCLUSIVE TRANSACTION;
        CREATE TABLE plugin_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            publisher_key_id TEXT NOT NULL,
            plugin_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            schema_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX plugin_events_owner_order_index
            ON plugin_events(publisher_key_id, plugin_id, id DESC);
        PRAGMA user_version = 12;
        COMMIT;
        ",
    ).expect("Failed to add schema-checked plugin-owned events");
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EventCorrection {
    pub corrected_at: DateTime<Utc>,
    pub source: String,
    pub fields: Vec<String>,
}

pub struct DatastoreInstance {
    buckets_cache: HashMap<String, Bucket>,
    first_init: bool,
    pub db_version: i32,
}

impl DatastoreInstance {
    pub fn new(
        conn: &Connection,
        migrate_enabled: bool,
        encrypted: bool,
    ) -> Result<DatastoreInstance, DatastoreError> {
        let mut first_init = false;
        let db_version = _get_db_version(conn);

        if migrate_enabled {
            first_init = _create_tables(conn, db_version, encrypted);
        } else if db_version < 0 {
            return Err(DatastoreError::Uninitialized(
                "Tried to open an uninitialized datastore with migration disabled".to_string(),
            ));
        } else if db_version != NEWEST_DB_VERSION {
            return Err(DatastoreError::OldDbVersion(format!(
                "\
                Tried to open an database with an incompatible database version!
                Database has version {db_version} while the supported version is {NEWEST_DB_VERSION}"
            )));
        }

        let mut ds = DatastoreInstance {
            buckets_cache: HashMap::new(),
            first_init,
            db_version,
        };
        ds.get_stored_buckets(conn)?;
        Ok(ds)
    }

    fn get_stored_buckets(&mut self, conn: &Connection) -> Result<(), DatastoreError> {
        let mut stmt = match conn.prepare_cached(
            "
            SELECT  buckets.id, buckets.name, buckets.type, buckets.client,
                    buckets.hostname, buckets.created,
                    min(events.starttime), max(events.endtime),
                    buckets.data
            FROM buckets
            LEFT OUTER JOIN events ON buckets.id = events.bucketrow
            GROUP BY buckets.id
            ;",
        ) {
            Ok(stmt) => stmt,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to prepare get_stored_buckets SQL statement: {err}"
                )))
            }
        };
        let buckets = match stmt.query_map(&[] as &[&dyn ToSql], |row| {
            let opt_start_ns: Option<i64> = row.get(6)?;
            let opt_start = match opt_start_ns {
                Some(starttime_ns) => {
                    let seconds: i64 = starttime_ns / 1_000_000_000;
                    let subnanos: u32 = (starttime_ns % 1_000_000_000) as u32;
                    Some(DateTime::from_timestamp(seconds, subnanos).unwrap())
                }
                None => None,
            };

            let opt_end_ns: Option<i64> = row.get(7)?;
            let opt_end = match opt_end_ns {
                Some(endtime_ns) => {
                    let seconds: i64 = endtime_ns / 1_000_000_000;
                    let subnanos: u32 = (endtime_ns % 1_000_000_000) as u32;
                    Some(DateTime::from_timestamp(seconds, subnanos).unwrap())
                }
                None => None,
            };

            // If data column is not set (possible on old installations), use an empty map as default
            let data_str: String = row.get(8)?;
            let data_json = match serde_json::from_str(&data_str) {
                Ok(data) => data,
                Err(e) => {
                    return Err(rusqlite::Error::InvalidColumnName(format!(
                        "Failed to parse data to JSON: {e:?}"
                    )))
                }
            };

            Ok(Bucket {
                bid: row.get(0)?,
                id: row.get(1)?,
                _type: row.get(2)?,
                client: row.get(3)?,
                hostname: row.get(4)?,
                created: row.get(5)?,
                data: data_json,
                metadata: BucketMetadata {
                    start: opt_start,
                    end: opt_end,
                },
                events: None,
                last_updated: None,
            })
        }) {
            Ok(buckets) => buckets,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to query get_stored_buckets SQL statement: {err:?}"
                )))
            }
        };
        for bucket in buckets {
            match bucket {
                Ok(b) => {
                    self.buckets_cache.insert(b.id.clone(), b.clone());
                }
                Err(e) => {
                    return Err(DatastoreError::InternalError(format!(
                        "Failed to parse bucket from SQLite, database is corrupt! {e:?}"
                    )))
                }
            }
        }
        Ok(())
    }

    pub fn reload_buckets(&mut self, conn: &Connection) -> Result<(), DatastoreError> {
        self.buckets_cache.clear();
        self.get_stored_buckets(conn)
    }

    pub fn ensure_legacy_import(&mut self, conn: &Connection) -> Result<bool, ()> {
        use super::legacy_import::legacy_import;
        if !self.first_init {
            Ok(false)
        } else {
            self.first_init = false;
            match legacy_import(self, conn) {
                Ok(_) => {
                    info!("Successfully imported legacy database");
                    self.get_stored_buckets(conn).unwrap();
                    Ok(true)
                }
                Err(err) => {
                    warn!("Failed to import legacy database: {:?}", err);
                    Err(())
                }
            }
        }
    }

    pub fn create_bucket(
        &mut self,
        conn: &Connection,
        mut bucket: Bucket,
    ) -> Result<(), DatastoreError> {
        bucket.created = match bucket.created {
            Some(created) => Some(created),
            None => Some(Utc::now()),
        };
        let mut stmt = match conn.prepare_cached(
            "
                INSERT INTO buckets (name, type, client, hostname, created, data)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ) {
            Ok(buckets) => buckets,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to prepare create_bucket SQL statement: {err}"
                )))
            }
        };
        let data = serde_json::to_string(&bucket.data).unwrap();
        let res = stmt.execute([
            &bucket.id,
            &bucket._type,
            &bucket.client,
            &bucket.hostname,
            &bucket.created as &dyn ToSql,
            &data,
        ]);

        match res {
            Ok(_) => {
                info!("Created bucket {}", bucket.id);
                // Get and set rowid
                let rowid: i64 = conn.last_insert_rowid();
                bucket.bid = Some(rowid);
                // Take out events from struct before caching
                let events = bucket.events;
                bucket.events = None;
                // Cache bucket
                self.buckets_cache.insert(bucket.id.clone(), bucket.clone());
                // Insert events
                if let Some(events) = events {
                    self.insert_events(conn, &bucket.id, events.take_inner())?;
                    bucket.events = None;
                }
                Ok(())
            }
            // FIXME: This match is ugly, is it possible to write it in a cleaner way?
            Err(err) => match err {
                rusqlite::Error::SqliteFailure { 0: sqlerr, 1: _ } => match sqlerr.code {
                    rusqlite::ErrorCode::ConstraintViolation => {
                        Err(DatastoreError::BucketAlreadyExists(bucket.id.to_string()))
                    }
                    _ => Err(DatastoreError::InternalError(format!(
                        "Failed to execute create_bucket SQL statement: {err}"
                    ))),
                },
                _ => Err(DatastoreError::InternalError(format!(
                    "Failed to execute create_bucket SQL statement: {err}"
                ))),
            },
        }
    }

    pub fn delete_bucket(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
    ) -> Result<(), DatastoreError> {
        let bucket = (self.get_bucket(bucket_id))?;
        let bucketrow = bucket.bid.unwrap();
        with_savepoint(conn, "peakactivity_delete_bucket", || {
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            for event in self.get_events_unclipped(conn, bucket_id, None, None, None)? {
                self.record_local_tombstone(conn, bucket_id, &event)?;
            }
            conn.execute("DELETE FROM event_corrections WHERE bucketrow = ?1", [&bucketrow])
                .map_err(|_| DatastoreError::InternalError("Failed to delete correction history".into()))?;
            conn.execute("DELETE FROM events WHERE bucketrow = ?1", [&bucketrow])
                .map_err(|_| DatastoreError::InternalError("Failed to delete bucket events".into()))?;
            conn.execute("DELETE FROM buckets WHERE id = ?1", [&bucketrow])
                .map_err(|_| DatastoreError::InternalError("Failed to delete bucket".into()))?;
            Ok(())
        })?;
        self.buckets_cache.remove(bucket_id);
        Ok(())
    }

    pub fn get_bucket(&self, bucket_id: &str) -> Result<Bucket, DatastoreError> {
        let cached_bucket = self.buckets_cache.get(bucket_id);
        match cached_bucket {
            Some(bucket) => Ok(bucket.clone()),
            None => Err(DatastoreError::NoSuchBucket(bucket_id.to_string())),
        }
    }

    pub fn get_buckets(&self) -> HashMap<String, Bucket> {
        self.buckets_cache.clone()
    }

    pub fn insert_events(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        events: Vec<Event>,
    ) -> Result<Vec<Event>, DatastoreError> {
        self.insert_events_inner(conn, bucket_id, events, true)
    }

    fn insert_events_inner(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        mut events: Vec<Event>,
        journal_sync: bool,
    ) -> Result<Vec<Event>, DatastoreError> {
        #[cfg(not(any(feature = "encryption", feature = "encryption-vendored")))]
        let _ = journal_sync;
        let result = with_savepoint(conn, "peakactivity_insert_events", || {
            let mut bucket = self.get_bucket(bucket_id)?;
            let mut stmt = conn.prepare_cached(
                "INSERT OR REPLACE INTO events(bucketrow,id,starttime,endtime,data) VALUES (?1,?2,?3,?4,?5)",
            ).map_err(|err| DatastoreError::InternalError(format!("Failed to prepare insert_events SQL statement: {err}")))?;
            for event in &mut events {
                let starttime_nanos = event.timestamp.timestamp_nanos_opt().unwrap();
                let duration_nanos = event.duration.num_nanoseconds().ok_or_else(|| {
                    DatastoreError::InternalError("Failed to convert duration to nanoseconds".into())
                })?;
                let endtime_nanos = starttime_nanos + duration_nanos;
                let data = serde_json::to_string(&event.data).unwrap();
                stmt.execute([
                    &bucket.bid.unwrap(),
                    &event.id as &dyn ToSql,
                    &starttime_nanos,
                    &endtime_nanos,
                    &data as &dyn ToSql,
                ]).map_err(|err| DatastoreError::InternalError(format!("Failed to insert event: {event:?}, {err}")))?;
                self.update_endtime(&mut bucket, event);
                event.id = Some(conn.last_insert_rowid());
                #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
                if journal_sync { self.record_local_upsert(conn, bucket_id, event)?; }
            }
            Ok(events)
        });
        if result.is_err() { self.reload_buckets(conn)?; }
        result
    }

    pub fn delete_events_by_id(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        event_ids: Vec<i64>,
    ) -> Result<(), DatastoreError> {
        let bucket = self.get_bucket(bucket_id)?;
        let bucketrow = bucket.bid.unwrap();
        with_savepoint(conn, "peakactivity_delete_events", || {
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            for id in &event_ids {
                let exists = conn.query_row(
                    "SELECT 1 FROM events WHERE bucketrow = ?1 AND id = ?2",
                    params![bucketrow, id],
                    |_| Ok(()),
                ).optional().map_err(|_| DatastoreError::InternalError("Could not inspect deleted events".into()))?.is_some();
                if exists {
                    let event = self.get_event(conn, bucket_id, *id)?;
                    self.record_local_tombstone(conn, bucket_id, &event)?;
                }
            }
            let mut correction_stmt = conn.prepare_cached(
                "DELETE FROM event_corrections WHERE bucketrow = ?1 AND event_id = ?2",
            ).map_err(|_| DatastoreError::InternalError("Failed to prepare correction cleanup".into()))?;
            let mut stmt = conn.prepare_cached(
                "DELETE FROM events WHERE bucketrow = ?1 AND id = ?2",
            ).map_err(|_| DatastoreError::InternalError("Failed to prepare event deletion".into()))?;
            for id in event_ids {
                correction_stmt.execute([&bucketrow, &id])
                    .map_err(|_| DatastoreError::InternalError("Failed to delete correction history".into()))?;
                stmt.execute([&bucketrow, &id as &dyn ToSql])
                    .map_err(|_| DatastoreError::InternalError("Failed to delete event".into()))?;
            }
            Ok(())
        })?;
        self.reload_buckets(conn)?;
        Ok(())
    }

    pub fn delete_events_in_range(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<u64, DatastoreError> {
        if start >= end { return Err(DatastoreError::InvalidTimeRange); }
        let bucket = self.get_bucket(bucket_id)?;
        let start_ns = start.timestamp_nanos_opt().ok_or(DatastoreError::InvalidTimeRange)?;
        let end_ns = end.timestamp_nanos_opt().ok_or(DatastoreError::InvalidTimeRange)?;
        let bucketrow = bucket.bid.unwrap();
        let removed = with_savepoint(conn, "peakactivity_delete_range", || {
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            for event in self.get_events_unclipped(conn, bucket_id, Some(start), Some(end), None)? {
                self.record_local_tombstone(conn, bucket_id, &event)?;
            }
            conn.execute(
                "DELETE FROM event_corrections WHERE bucketrow = ?1 AND event_id IN (SELECT id FROM events WHERE bucketrow = ?1 AND endtime >= ?2 AND starttime <= ?3)",
                [&bucketrow, &start_ns, &end_ns],
            ).map_err(|_| DatastoreError::InternalError("Failed to delete correction history".into()))?;
            let removed = conn.execute(
                "DELETE FROM events WHERE bucketrow = ?1 AND endtime >= ?2 AND starttime <= ?3",
                [&bucketrow, &start_ns, &end_ns],
            ).map_err(|_| DatastoreError::InternalError("Failed to delete events in time range".into()))?;
            Ok(removed as u64)
        })?;
        self.reload_buckets(conn)?;
        Ok(removed)
    }

    fn update_endtime(&mut self, bucket: &mut Bucket, event: &Event) {
        let mut update = false;
        /* Potentially update start */
        match bucket.metadata.start {
            None => {
                bucket.metadata.start = Some(event.timestamp);
                update = true;
            }
            Some(current_start) => {
                if current_start > event.timestamp {
                    bucket.metadata.start = Some(event.timestamp);
                    update = true;
                }
            }
        }
        /* Potentially update end */
        let event_endtime = event.calculate_endtime();
        match bucket.metadata.end {
            None => {
                bucket.metadata.end = Some(event_endtime);
                update = true;
            }
            Some(current_end) => {
                if current_end < event_endtime {
                    bucket.metadata.end = Some(event_endtime);
                    update = true;
                }
            }
        }
        /* Update buchets_cache if start or end has been updated */
        if update {
            self.buckets_cache.insert(bucket.id.clone(), bucket.clone());
        }
    }

    pub fn replace_last_event(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        event_id: i64,
        event: &Event,
    ) -> Result<(), DatastoreError> {
        let mut bucket = self.get_bucket(bucket_id)?;
        let previous = self.get_event(conn, bucket_id, event_id)?;
        let mut corrected = event.clone();
        corrected.id = Some(event_id);

        let result = with_savepoint(conn, "peakactivity_replace_last_event", || {
            let starttime_nanos = corrected.timestamp.timestamp_nanos_opt().unwrap();
            let duration_nanos = corrected.duration.num_nanoseconds()
                .ok_or_else(|| DatastoreError::InternalError("Failed to convert duration to nanoseconds".into()))?;
            let endtime_nanos = starttime_nanos + duration_nanos;
            let data = serde_json::to_string(&corrected.data).unwrap();
            let changed = conn.execute(
                "UPDATE events SET starttime = ?2,endtime = ?3,data = ?4 WHERE bucketrow = ?1 AND id = ?5",
                params![bucket.bid.unwrap(), starttime_nanos, endtime_nanos, data, event_id],
            ).map_err(|_| DatastoreError::InternalError("Heartbeat event could not be updated".into()))?;
            if changed == 0 {
                return Err(DatastoreError::InternalError(format!("replace_last_event matched 0 rows for event_id {event_id} - cache/DB inconsistency")));
            }
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            self.record_local_correction(conn, bucket_id, &previous, &corrected)?;
            Ok(())
        });
        if result.is_err() { self.reload_buckets(conn)?; }
        result?;
        self.update_endtime(&mut bucket, &corrected);
        Ok(())
    }

    pub fn heartbeat(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        heartbeat: Event,
        pulsetime: f64,
        last_heartbeat: &mut HashMap<String, Option<Event>>,
    ) -> Result<Event, DatastoreError> {
        self.get_bucket(bucket_id)?;
        if !last_heartbeat.contains_key(bucket_id) {
            last_heartbeat.insert(bucket_id.to_string(), None);
        }
        let last_event = match last_heartbeat.remove(bucket_id).unwrap() {
            // last heartbeat is in cache
            Some(last_event) => last_event,
            None => {
                // last heartbeat was not in cache, fetch from DB
                let mut last_event_vec = self.get_events(conn, bucket_id, None, None, Some(1))?;
                match last_event_vec.pop() {
                    Some(last_event) => last_event,
                    None => {
                        // There was no last event, insert and return
                        let mut inserted = self.insert_events(conn, bucket_id, vec![heartbeat])?;
                        return Ok(inserted.pop().unwrap());
                    }
                }
            }
        };
        let inserted_heartbeat = match aw_transform::heartbeat(&last_event, &heartbeat, pulsetime) {
            Some(mut merged_heartbeat) => {
                debug!("Merged heartbeat successfully");
                // Use the event ID from last_event to ensure we update the correct row
                let event_id = last_event.id.ok_or_else(|| {
                    DatastoreError::InternalError("last_event has no ID".to_string())
                })?;
                self.replace_last_event(conn, bucket_id, event_id, &merged_heartbeat)?;
                // Preserve the event ID on the cached heartbeat so subsequent
                // heartbeats can look it up for replace_last_event
                merged_heartbeat.id = Some(event_id);
                merged_heartbeat
            }
            None => {
                debug!("Failed to merge heartbeat");
                // insert_events sets the ID on the events in the vec, so use the
                // returned event (with ID) instead of the original heartbeat
                let mut inserted = self.insert_events(conn, bucket_id, vec![heartbeat])?;
                inserted.pop().unwrap()
            }
        };
        last_heartbeat.insert(bucket_id.to_string(), Some(inserted_heartbeat.clone()));
        Ok(inserted_heartbeat)
    }

    pub fn get_event(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        event_id: i64,
    ) -> Result<Event, DatastoreError> {
        let bucket = self.get_bucket(bucket_id)?;

        let mut stmt = match conn.prepare_cached(
            "
                SELECT id, starttime, endtime, data
                FROM events
                WHERE bucketrow = ?1
                    AND id = ?2
                LIMIT 1
            ;",
        ) {
            Ok(stmt) => stmt,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to prepare get_event SQL statement: {err}"
                )))
            }
        };

        // TODO: Refactor to share row-parsing logic with get_events
        let row = match stmt.query_row([&bucket.bid.unwrap(), &event_id], |row| {
            let id = row.get(0)?;
            let starttime_ns: i64 = row.get(1)?;
            let endtime_ns: i64 = row.get(2)?;
            let data_str: String = row.get(3)?;

            let time_seconds: i64 = starttime_ns / 1_000_000_000;
            let time_subnanos: u32 = (starttime_ns % 1_000_000_000) as u32;
            let duration_ns = endtime_ns - starttime_ns;
            let data: serde_json::map::Map<String, Value> =
                serde_json::from_str(&data_str).unwrap();

            Ok(Event {
                id: Some(id),
                timestamp: DateTime::from_timestamp(time_seconds, time_subnanos).unwrap(),
                duration: Duration::nanoseconds(duration_ns),
                data,
            })
        }) {
            Ok(rows) => rows,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Err(DatastoreError::NoSuchEvent(event_id.to_string())),
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to map get_event SQL statement: {err}"
                )))
            }
        };

        Ok(row)
    }

    pub(crate) fn replace_events_atomic(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        old_ids: &[i64],
        replacements: Vec<Event>,
        source: &str,
        fields: &[&str],
    ) -> Result<Vec<Event>, DatastoreError> {
        if old_ids.is_empty() || replacements.is_empty() || source.is_empty() || fields.is_empty()
            || old_ids.iter().copied().collect::<BTreeSet<_>>().len() != old_ids.len()
        {
            return Err(DatastoreError::InvalidCorrection("Event transformation is invalid".into()));
        }
        let bucket = self.get_bucket(bucket_id)?;
        let bucketrow = bucket.bid.ok_or_else(|| DatastoreError::NoSuchBucket(bucket_id.into()))?;
        for id in old_ids { self.get_event(conn, bucket_id, *id)?; }
        for event in &replacements {
            let end = event.timestamp.checked_add_signed(event.duration)
                .ok_or_else(|| DatastoreError::InvalidCorrection("Event time range is invalid".into()))?;
            if event.id.is_some() || event.duration <= Duration::zero()
                || event.timestamp.timestamp_nanos_opt().is_none() || end.timestamp_nanos_opt().is_none()
            {
                return Err(DatastoreError::InvalidCorrection("Replacement event is invalid".into()));
            }
        }

        let corrected_at = Utc::now();
        let fields = serde_json::to_string(fields)
            .map_err(|_| DatastoreError::InternalError("Correction provenance could not be encoded".into()))?;
        let result = with_savepoint(conn, "peakactivity_event_transform", || {
            for id in old_ids {
                #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
                {
                    let event = self.get_event(conn, bucket_id, *id)?;
                    self.record_local_tombstone(conn, bucket_id, &event)?;
                }
                conn.execute(
                    "DELETE FROM event_corrections WHERE bucketrow = ?1 AND event_id = ?2",
                    params![bucketrow, id],
                ).map_err(|_| DatastoreError::InternalError("Prior correction metadata could not be removed".into()))?;
                let removed = conn.execute(
                    "DELETE FROM events WHERE bucketrow = ?1 AND id = ?2",
                    params![bucketrow, id],
                ).map_err(|_| DatastoreError::InternalError("Prior event could not be replaced".into()))?;
                if removed == 0 { return Err(DatastoreError::NoSuchEvent(id.to_string())); }
            }
            let inserted = self.insert_events(conn, bucket_id, replacements)?;
            for event in &inserted {
                let event_id = event.id.ok_or_else(|| DatastoreError::InternalError("Replacement event has no ID".into()))?;
                conn.execute(
                    "INSERT INTO event_corrections(bucketrow, event_id, corrected_at, source, fields) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![bucketrow, event_id, corrected_at, source, &fields],
                ).map_err(|_| DatastoreError::InternalError("Transformation provenance could not be saved".into()))?;
            }
            Ok(inserted)
        });
        if result.is_err() { self.reload_buckets(conn)?; }
        let result = result?;
        self.reload_buckets(conn)?;
        Ok(result)
    }

    pub(crate) fn correct_event(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        event: &Event,
        source: &str,
    ) -> Result<Event, DatastoreError> {
        self.correct_events(conn, bucket_id, std::slice::from_ref(event), source)?
            .into_iter().next()
            .ok_or_else(|| DatastoreError::InternalError("Correction returned no event".into()))
    }

    pub(crate) fn correct_events(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        events: &[Event],
        source: &str,
    ) -> Result<Vec<Event>, DatastoreError> {
        if events.is_empty() { return Ok(Vec::new()); }
        let result = with_savepoint(conn, "peakactivity_corrections", || {
            events.iter().map(|event| self.correct_event_record(conn, bucket_id, event, source))
                .collect::<Result<Vec<_>, _>>()
        });
        if result.is_err() { self.reload_buckets(conn)?; }
        let result = result?;
        self.reload_buckets(conn)?;
        Ok(result)
    }

    fn correct_event_record(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        event: &Event,
        source: &str,
    ) -> Result<Event, DatastoreError> {
        let event_id = event.id.ok_or_else(|| DatastoreError::InvalidCorrection("An event ID is required".into()))?;
        if event.duration < Duration::zero() || event.duration.num_nanoseconds().is_none() {
            return Err(DatastoreError::InvalidCorrection("Event duration is invalid".into()));
        }
        let end = event.timestamp.checked_add_signed(event.duration)
            .ok_or_else(|| DatastoreError::InvalidCorrection("Event time range is invalid".into()))?;
        let start_ns = event.timestamp.timestamp_nanos_opt()
            .ok_or_else(|| DatastoreError::InvalidCorrection("Event timestamp is out of range".into()))?;
        let end_ns = end.timestamp_nanos_opt()
            .ok_or_else(|| DatastoreError::InvalidCorrection("Event end time is out of range".into()))?;
        let bucket = self.get_bucket(bucket_id)?;
        let bucketrow = bucket.bid.unwrap();
        let previous = self.get_event(conn, bucket_id, event_id)?;
        if previous == *event { return Ok(event.clone()); }

        let mut fields = BTreeSet::new();
        if previous.timestamp != event.timestamp { fields.insert("timestamp".to_string()); }
        if previous.duration != event.duration { fields.insert("duration".to_string()); }
        for key in previous.data.keys().chain(event.data.keys()) {
            if previous.data.get(key) != event.data.get(key) { fields.insert(key.clone()); }
        }
        let fields: Vec<_> = fields.into_iter().collect();
        if fields.is_empty() { return Ok(event.clone()); }
        let data = serde_json::to_string(&event.data)
            .map_err(|_| DatastoreError::InternalError("Corrected event could not be encoded".into()))?;
        let corrected_at = Utc::now();
        let fields = serde_json::to_string(&fields).unwrap();
        let changed = conn.execute(
            "UPDATE events SET starttime = ?3, endtime = ?4, data = ?5 WHERE bucketrow = ?1 AND id = ?2",
            params![bucketrow, event_id, start_ns, end_ns, &data],
        ).map_err(|_| DatastoreError::InternalError("Corrected event could not be saved".into()))?;
        if changed == 0 { return Err(DatastoreError::NoSuchEvent(event_id.to_string())); }
        conn.execute(
            "INSERT INTO event_corrections(bucketrow, event_id, corrected_at, source, fields) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![bucketrow, event_id, corrected_at, source, &fields],
        ).map_err(|_| DatastoreError::InternalError("Correction provenance could not be saved".into()))?;
        #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
        self.record_local_correction(conn, bucket_id, &previous, event)?;
        Ok(event.clone())
    }

    pub(crate) fn get_event_corrections(
        &self,
        conn: &Connection,
        bucket_id: &str,
        event_id: i64,
    ) -> Result<Vec<EventCorrection>, DatastoreError> {
        let bucket = self.get_bucket(bucket_id)?;
        let bucketrow = bucket.bid.unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT corrected_at, source, fields FROM event_corrections WHERE bucketrow = ?1 AND event_id = ?2 ORDER BY id",
        ).map_err(|_| DatastoreError::InternalError("Correction history could not be read".into()))?;
        let rows = stmt.query_map([&bucketrow, &event_id], |row| {
            let fields: String = row.get(2)?;
            Ok(EventCorrection {
                corrected_at: row.get(0)?,
                source: row.get(1)?,
                fields: serde_json::from_str(&fields).map_err(|_| rusqlite::Error::InvalidQuery)?,
            })
        }).map_err(|_| DatastoreError::InternalError("Correction history could not be read".into()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| DatastoreError::InternalError("Correction history could not be read".into()))
    }

    fn get_events_inner(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        starttime_opt: Option<DateTime<Utc>>,
        endtime_opt: Option<DateTime<Utc>>,
        limit_opt: Option<u64>,
        clip_to_query_range: bool,
    ) -> Result<Vec<Event>, DatastoreError> {
        let bucket = self.get_bucket(bucket_id)?;

        let mut list = Vec::new();

        let starttime_filter_ns: i64 = match starttime_opt {
            Some(dt) => dt.timestamp_nanos_opt().unwrap(),
            None => 0,
        };
        let endtime_filter_ns: i64 = match endtime_opt {
            Some(dt) => dt.timestamp_nanos_opt().unwrap(),
            None => std::i64::MAX,
        };
        if starttime_filter_ns > endtime_filter_ns {
            warn!("Starttime in event query was lower than endtime!");
            return Ok(list);
        }
        let limit = match limit_opt {
            Some(l) => l as i64,
            None => -1,
        };

        let mut stmt = match conn.prepare_cached(
            "
                SELECT id, starttime, endtime, data
                FROM events
                WHERE bucketrow = ?1
                    AND endtime >= ?2
                    AND starttime <= ?3
                ORDER BY starttime DESC, id DESC
                LIMIT ?4
            ;",
        ) {
            Ok(stmt) => stmt,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to prepare get_events SQL statement: {err}"
                )))
            }
        };

        let rows = match stmt.query_map(
            [
                &bucket.bid.unwrap(),
                &starttime_filter_ns,
                &endtime_filter_ns,
                &limit,
            ],
            |row| {
                let id = row.get(0)?;
                let mut starttime_ns: i64 = row.get(1)?;
                let mut endtime_ns: i64 = row.get(2)?;
                let data_str: String = row.get(3)?;

                if clip_to_query_range {
                    if starttime_ns < starttime_filter_ns {
                        starttime_ns = starttime_filter_ns
                    }
                    if endtime_ns > endtime_filter_ns {
                        endtime_ns = endtime_filter_ns
                    }
                }
                let duration_ns = endtime_ns - starttime_ns;

                let time_seconds: i64 = starttime_ns / 1_000_000_000;
                let time_subnanos: u32 = (starttime_ns % 1_000_000_000) as u32;
                let data: serde_json::map::Map<String, Value> =
                    serde_json::from_str(&data_str).unwrap();

                Ok(Event {
                    id: Some(id),
                    timestamp: DateTime::from_timestamp(time_seconds, time_subnanos).unwrap(),
                    duration: Duration::nanoseconds(duration_ns),
                    data,
                })
            },
        ) {
            Ok(rows) => rows,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to map get_events SQL statement: {err}"
                )))
            }
        };
        for row in rows {
            match row {
                Ok(event) => list.push(event),
                Err(err) => warn!("Corrupt event in bucket {}: {}", bucket_id, err),
            };
        }

        Ok(list)
    }

    pub fn get_events(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        starttime_opt: Option<DateTime<Utc>>,
        endtime_opt: Option<DateTime<Utc>>,
        limit_opt: Option<u64>,
    ) -> Result<Vec<Event>, DatastoreError> {
        self.get_events_inner(conn, bucket_id, starttime_opt, endtime_opt, limit_opt, true)
    }

    pub fn get_events_unclipped(
        &mut self,
        conn: &Connection,
        bucket_id: &str,
        starttime_opt: Option<DateTime<Utc>>,
        endtime_opt: Option<DateTime<Utc>>,
        limit_opt: Option<u64>,
    ) -> Result<Vec<Event>, DatastoreError> {
        self.get_events_inner(
            conn,
            bucket_id,
            starttime_opt,
            endtime_opt,
            limit_opt,
            false,
        )
    }

    pub fn get_event_count(
        &self,
        conn: &Connection,
        bucket_id: &str,
        starttime_opt: Option<DateTime<Utc>>,
        endtime_opt: Option<DateTime<Utc>>,
    ) -> Result<i64, DatastoreError> {
        let bucket = self.get_bucket(bucket_id)?;

        let starttime_filter_ns: i64 = match starttime_opt {
            Some(dt) => dt.timestamp_nanos_opt().unwrap(),
            None => 0,
        };
        let endtime_filter_ns: i64 = match endtime_opt {
            Some(dt) => dt.timestamp_nanos_opt().unwrap(),
            None => std::i64::MAX,
        };
        if starttime_filter_ns >= endtime_filter_ns {
            warn!("Endtime in event query was same or lower than starttime!");
            return Ok(0);
        }

        let mut stmt = match conn.prepare_cached(
            "
            SELECT count(*) FROM events
            WHERE bucketrow = ?1
                AND endtime >= ?2
                AND starttime <= ?3",
        ) {
            Ok(stmt) => stmt,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to prepare get_event_count SQL statement: {err}",
                )))
            }
        };

        let count = match stmt.query_row(
            [
                &bucket.bid.unwrap(),
                &starttime_filter_ns,
                &endtime_filter_ns,
            ],
            |row| row.get(0),
        ) {
            Ok(count) => count,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to query get_event_count SQL statement: {err}"
                )))
            }
        };

        Ok(count)
    }

    pub fn insert_key_value(
        &self,
        conn: &Connection,
        key: &str,
        data: &str,
    ) -> Result<(), DatastoreError> {
        let mut stmt = match conn.prepare_cached(
            "
                INSERT OR REPLACE INTO key_value(key, value, last_modified)
                VALUES (?1, ?2, ?3)",
        ) {
            Ok(stmt) => stmt,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to prepare insert_value SQL statement: {err}"
                )))
            }
        };
        let timestamp = Utc::now().timestamp();
        #[allow(clippy::expect_fun_call)]
        stmt.execute(params![key, data, &timestamp])
            .expect(&format!("Failed to insert key-value pair: {key}"));
        Ok(())
    }

    pub fn delete_key_value(&self, conn: &Connection, key: &str) -> Result<(), DatastoreError> {
        conn.execute("DELETE FROM key_value WHERE key = ?1", [key])
            .expect("Error deleting value from database");
        Ok(())
    }

    pub fn get_key_value(&self, conn: &Connection, key: &str) -> Result<String, DatastoreError> {
        let mut stmt = match conn.prepare_cached(
            "
                SELECT * FROM key_value WHERE KEY = ?1",
        ) {
            Ok(stmt) => stmt,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to prepare get_value SQL statement: {err}"
                )))
            }
        };

        match stmt.query_row([key], |row| row.get(1)) {
            Ok(result) => Ok(result),
            Err(err) => match err {
                rusqlite::Error::QueryReturnedNoRows => {
                    Err(DatastoreError::NoSuchKey(key.to_string()))
                }
                _ => Err(DatastoreError::InternalError(format!(
                    "Get value query failed for key {key}"
                ))),
            },
        }
    }

    pub fn get_key_values(
        &self,
        conn: &Connection,
        pattern: &str,
    ) -> Result<HashMap<String, String>, DatastoreError> {
        let mut stmt =
            match conn.prepare_cached("SELECT key, value FROM key_value WHERE key LIKE ?") {
                Ok(stmt) => stmt,
                Err(err) => {
                    return Err(DatastoreError::InternalError(format!(
                        "Failed to prepare get_value SQL statement: {err}"
                    )))
                }
            };

        let mut output = HashMap::<String, String>::new();
        // Rusqlite's get wants index and item type as parameters.
        let result = stmt.query_map([pattern], |row| {
            Ok((row.get::<usize, String>(0)?, row.get::<usize, String>(1)?))
        });
        match result {
            Ok(settings) => {
                for row in settings {
                    // Unwrap to String or panic on SQL row if type is invalid. Can't happen with a
                    // properly initialized table.
                    let (key, value) = row.unwrap();
                    // Only return keys starting with "settings.".
                    if !key.starts_with("settings.") || key == AI_SETTINGS_KEY || key == AI_HISTORY_KEY {
                        continue;
                    }
                    output.insert(key, value);
                }
                Ok(output)
            }
            Err(err) => match err {
                rusqlite::Error::QueryReturnedNoRows => Ok(output),
                _ => Err(DatastoreError::InternalError(
                    "Failed to get settings".to_string(),
                )),
            },
        }
    }

    fn plugin_storage_quota(manifest: &PluginManifestV1) -> Result<u64, DatastoreError> {
        manifest.validate()
            .map_err(|_| DatastoreError::InternalError("Plugin manifest is invalid".into()))?;
        let storage = manifest.capabilities.storage.as_ref()
            .filter(|storage| storage.encrypted && storage.quota_bytes > 0 && storage.quota_bytes <= PLUGIN_MAX_STORAGE_BYTES_V1)
            .ok_or_else(|| DatastoreError::InternalError("Plugin has no encrypted storage grant".into()))?;
        Ok(storage.quota_bytes)
    }

    pub fn get_plugin_storage(
        &self,
        conn: &Connection,
        manifest: &PluginManifestV1,
    ) -> Result<BTreeMap<String, Value>, DatastoreError> {
        let quota = Self::plugin_storage_quota(manifest)?;
        let mut statement = conn.prepare_cached(
            "SELECT storage_key,value_json FROM plugin_storage WHERE publisher_key_id = ?1 AND plugin_id = ?2 ORDER BY storage_key",
        ).map_err(|_| DatastoreError::InternalError("Plugin storage is unavailable".into()))?;
        let rows = statement.query_map(params![manifest.publisher_key_id, manifest.plugin_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).map_err(|_| DatastoreError::InternalError("Plugin storage is unavailable".into()))?;
        let mut output = BTreeMap::new();
        let mut bytes = 0_u64;
        for row in rows {
            let (key, value_json) = row.map_err(|_| DatastoreError::InternalError("Plugin storage record is invalid".into()))?;
            let value: Value = serde_json::from_str(&value_json)
                .map_err(|_| DatastoreError::InternalError("Plugin storage record is invalid".into()))?;
            bytes = bytes.checked_add(key.len() as u64)
                .and_then(|total| total.checked_add(value_json.len() as u64))
                .ok_or_else(|| DatastoreError::InternalError("Plugin storage quota is exceeded".into()))?;
            output.insert(key, value);
        }
        if bytes > quota {
            return Err(DatastoreError::InternalError("Plugin storage exceeds its current quota".into()));
        }
        Ok(output)
    }

    pub fn apply_plugin_storage_intents(
        &self,
        conn: &Connection,
        manifest: &PluginManifestV1,
        intents: &[PluginStorageIntentV1],
    ) -> Result<(), DatastoreError> {
        let quota = Self::plugin_storage_quota(manifest)?;
        if intents.len() > PLUGIN_MAX_GRANTS_V1 || intents.iter().any(|intent| {
            intent.key.is_empty() || intent.key.len() > 128 || intent.key.chars().any(char::is_control)
                || intent.value.as_ref().is_some_and(|value| serde_json::to_vec(value)
                    .map_or(true, |bytes| bytes.len() > PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1))
        }) {
            return Err(DatastoreError::InternalError("Plugin storage intent is invalid".into()));
        }
        with_savepoint(conn, "plugin_storage_apply", || {
            for intent in intents {
                if let Some(value) = &intent.value {
                    let value = serde_json::to_string(value)
                        .map_err(|_| DatastoreError::InternalError("Plugin storage value is invalid".into()))?;
                    conn.execute(
                        "INSERT INTO plugin_storage(publisher_key_id,plugin_id,storage_key,value_json) VALUES (?1,?2,?3,?4) ON CONFLICT(publisher_key_id,plugin_id,storage_key) DO UPDATE SET value_json = excluded.value_json",
                        params![manifest.publisher_key_id, manifest.plugin_id, intent.key, value],
                    ).map_err(|_| DatastoreError::InternalError("Plugin storage could not be written".into()))?;
                } else {
                    conn.execute("DELETE FROM plugin_storage WHERE publisher_key_id = ?1 AND plugin_id = ?2 AND storage_key = ?3", params![manifest.publisher_key_id, manifest.plugin_id, intent.key])
                        .map_err(|_| DatastoreError::InternalError("Plugin storage could not be deleted".into()))?;
                }
            }
            let bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(length(CAST(storage_key AS BLOB)) + length(CAST(value_json AS BLOB))),0) FROM plugin_storage WHERE publisher_key_id = ?1 AND plugin_id = ?2",
                params![manifest.publisher_key_id, manifest.plugin_id],
                |row| row.get(0),
            ).map_err(|_| DatastoreError::InternalError("Plugin storage quota is unavailable".into()))?;
            if u64::try_from(bytes).unwrap_or(u64::MAX) > quota {
                return Err(DatastoreError::InternalError("Plugin storage quota exceeded".into()));
            }
            Ok(())
        })
    }

    pub fn delete_plugin_storage(&self, conn: &Connection, manifest: &PluginManifestV1) -> Result<(), DatastoreError> {
        manifest.validate()
            .map_err(|_| DatastoreError::InternalError("Plugin manifest is invalid".into()))?;
        conn.execute("DELETE FROM plugin_storage WHERE publisher_key_id = ?1 AND plugin_id = ?2", params![manifest.publisher_key_id, manifest.plugin_id])
            .map_err(|_| DatastoreError::InternalError("Plugin storage could not be deleted".into()))?;
        Ok(())
    }

    pub fn get_plugin_events(
        &self,
        conn: &Connection,
        manifest: &PluginManifestV1,
    ) -> Result<Vec<PluginOwnedEventV1>, DatastoreError> {
        manifest.validate()
            .map_err(|_| DatastoreError::InternalError("Plugin manifest is invalid".into()))?;
        let mut statement = conn.prepare_cached(
            "SELECT id,event_type,schema_id,created_at,payload_json FROM plugin_events WHERE publisher_key_id = ?1 AND plugin_id = ?2 ORDER BY id DESC",
        ).map_err(|_| DatastoreError::InternalError("Plugin events are unavailable".into()))?;
        let rows = statement.query_map(params![manifest.publisher_key_id, manifest.plugin_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, String>(3)?, row.get::<_, String>(4)?))
        }).map_err(|_| DatastoreError::InternalError("Plugin events are unavailable".into()))?;
        rows.map(|row| {
            let (event_id, event_type, schema_id, created_at, payload_json) = row
                .map_err(|_| DatastoreError::InternalError("Plugin event is invalid".into()))?;
            Ok(PluginOwnedEventV1 {
                schema_version: 1,
                publisher_key_id: manifest.publisher_key_id.clone(),
                plugin_id: manifest.plugin_id.clone(),
                event_id: u64::try_from(event_id)
                    .map_err(|_| DatastoreError::InternalError("Plugin event is invalid".into()))?,
                event_type,
                schema_id,
                created_at: DateTime::parse_from_rfc3339(&created_at)
                    .map_err(|_| DatastoreError::InternalError("Plugin event is invalid".into()))?
                    .with_timezone(&Utc),
                payload: serde_json::from_str(&payload_json)
                    .map_err(|_| DatastoreError::InternalError("Plugin event is invalid".into()))?,
            })
        }).collect()
    }

    pub fn apply_plugin_write_intents(
        &self,
        conn: &Connection,
        manifest: &PluginManifestV1,
        intents: &[PluginWriteIntentV1],
    ) -> Result<(), DatastoreError> {
        manifest.validate()
            .map_err(|_| DatastoreError::InternalError("Plugin manifest is invalid".into()))?;
        if intents.len() > PLUGIN_MAX_GRANTS_V1 || intents.iter().any(|intent| {
            !manifest.capabilities.write.iter().any(|grant| grant.event_type == intent.event_type && grant.schema_id == intent.schema_id)
                || validate_plugin_write_intent_v1(intent).is_err()
        }) {
            return Err(DatastoreError::InternalError("Plugin write schema is unavailable or invalid".into()));
        }
        with_savepoint(conn, "plugin_event_apply", || {
            for intent in intents {
                let payload = serde_json::to_string(&intent.payload)
                    .map_err(|_| DatastoreError::InternalError("Plugin event payload is invalid".into()))?;
                conn.execute(
                    "INSERT INTO plugin_events(publisher_key_id,plugin_id,event_type,schema_id,created_at,payload_json) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![manifest.publisher_key_id, manifest.plugin_id, intent.event_type, intent.schema_id, Utc::now().to_rfc3339(), payload],
                ).map_err(|_| DatastoreError::InternalError("Plugin event could not be stored".into()))?;
            }
            let bytes: i64 = conn.query_row(
                "SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))),0) FROM plugin_events WHERE publisher_key_id = ?1 AND plugin_id = ?2",
                params![manifest.publisher_key_id, manifest.plugin_id],
                |row| row.get(0),
            ).map_err(|_| DatastoreError::InternalError("Plugin event quota is unavailable".into()))?;
            if u64::try_from(bytes).unwrap_or(u64::MAX) > PLUGIN_MAX_PLUGIN_EVENT_BYTES_V1 {
                return Err(DatastoreError::InternalError("Plugin-owned event quota exceeded".into()));
            }
            Ok(())
        })
    }

    pub fn delete_plugin_data(&self, conn: &Connection, manifest: &PluginManifestV1) -> Result<(), DatastoreError> {
        manifest.validate()
            .map_err(|_| DatastoreError::InternalError("Plugin manifest is invalid".into()))?;
        with_savepoint(conn, "plugin_data_delete", || {
            conn.execute("DELETE FROM plugin_storage WHERE publisher_key_id = ?1 AND plugin_id = ?2", params![manifest.publisher_key_id, manifest.plugin_id])
                .map_err(|_| DatastoreError::InternalError("Plugin storage could not be deleted".into()))?;
            conn.execute("DELETE FROM plugin_events WHERE publisher_key_id = ?1 AND plugin_id = ?2", params![manifest.publisher_key_id, manifest.plugin_id])
                .map_err(|_| DatastoreError::InternalError("Plugin events could not be deleted".into()))?;
            Ok(())
        })
    }

    pub fn egress_kill_switch(&self, conn: &Connection) -> Result<bool, DatastoreError> {
        match self.get_key_value(conn, EGRESS_KILL_SWITCH_KEY) {
            Ok(value) => Ok(value != "false"),
            Err(DatastoreError::NoSuchKey(_)) => Ok(true),
            Err(error) => Err(error),
        }
    }

    pub fn set_egress_kill_switch(&self, conn: &Connection, enabled: bool) -> Result<(), DatastoreError> {
        with_savepoint(conn, "egress_kill_switch", || {
            self.insert_key_value(conn, EGRESS_KILL_SWITCH_KEY, if enabled { "true" } else { "false" })?;
            if enabled { self.clear_egress_approvals(conn)?; }
            Ok(())
        })
    }

    pub fn insert_egress_receipt(
        &self,
        conn: &Connection,
        receipt: &EgressReceiptV1,
    ) -> Result<(), DatastoreError> {
        if receipt.schema_version != 1
            || receipt.allowed_fields.iter().any(|field| !field.starts_with('/') || field.chars().any(char::is_control))
        {
            return Err(DatastoreError::InternalError("Invalid egress receipt".into()));
        }
        let fields = serde_json::to_string(&receipt.allowed_fields)
            .map_err(|_| DatastoreError::InternalError("Invalid egress receipt".into()))?;
        let scope = serde_json::to_string(&receipt.scope)
            .map_err(|_| DatastoreError::InternalError("Invalid egress receipt".into()))?;
        let decision = serde_json::to_string(&receipt.decision)
            .map_err(|_| DatastoreError::InternalError("Invalid egress receipt".into()))?;
        let policy_version = i64::try_from(receipt.policy_version)
            .map_err(|_| DatastoreError::InternalError("Invalid egress receipt".into()))?;
        conn.execute(
            "INSERT INTO egress_receipts(created_at, destination_id, purpose_id, retention_id, allowed_fields, policy_version, scope, decision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![receipt.created_at.to_rfc3339(), receipt.destination_id, receipt.purpose_id,
                receipt.retention_id, fields, policy_version, scope, decision],
        ).map_err(|_| DatastoreError::InternalError("Could not store egress receipt".into()))?;
        Ok(())
    }

    pub fn get_egress_receipts(
        &self,
        conn: &Connection,
        limit: usize,
    ) -> Result<Vec<EgressReceiptV1>, DatastoreError> {
        let mut statement = conn.prepare_cached(
            "SELECT created_at, destination_id, purpose_id, retention_id, allowed_fields, policy_version, scope, decision FROM egress_receipts ORDER BY id DESC LIMIT ?1",
        ).map_err(|_| DatastoreError::InternalError("Could not query egress receipts".into()))?;
        let rows = statement.query_map([limit.min(1000) as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?, row.get::<_, String>(7)?))
        }).map_err(|_| DatastoreError::InternalError("Could not query egress receipts".into()))?;
        let rows: Vec<_> = rows.collect::<Result<_, _>>()
            .map_err(|_| DatastoreError::InternalError("Stored egress receipt is invalid".into()))?;
        rows.into_iter().map(|(created_at, destination_id, purpose_id, retention_id, fields, version, scope, decision)| {
            let created_at = DateTime::parse_from_rfc3339(&created_at)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| DatastoreError::InternalError("Stored egress receipt is invalid".into()))?;
            let allowed_fields = serde_json::from_str(&fields)
                .map_err(|_| DatastoreError::InternalError("Stored egress receipt is invalid".into()))?;
            let scope = serde_json::from_str(&scope)
                .map_err(|_| DatastoreError::InternalError("Stored egress receipt is invalid".into()))?;
            let decision = serde_json::from_str(&decision)
                .map_err(|_| DatastoreError::InternalError("Stored egress receipt is invalid".into()))?;
            Ok(EgressReceiptV1 {
                schema_version: 1,
                destination_id,
                purpose_id,
                retention_id,
                allowed_fields,
                policy_version: u64::try_from(version)
                    .map_err(|_| DatastoreError::InternalError("Stored egress receipt is invalid".into()))?,
                scope,
                decision,
                created_at,
            })
        }).collect()
    }

    pub fn get_or_create_egress_secrets(&self, conn: &Connection) -> Result<EgressSecrets, DatastoreError> {
        let alias_secret = self.get_or_create_egress_secret(conn, EGRESS_ALIAS_SECRET_KEY)?;
        let approval_secret = self.get_or_create_egress_secret(conn, EGRESS_APPROVAL_SECRET_KEY)?;
        Ok(EgressSecrets::new(alias_secret, approval_secret))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn sync_journal_active(&self, conn: &Connection) -> Result<bool, DatastoreError> {
        conn.query_row("SELECT active FROM sync_journal_state WHERE id = 1", [], |row| row.get(0))
            .optional()
            .map(|active: Option<bool>| active.unwrap_or(false))
            .map_err(|_| DatastoreError::InternalError("Sync journal state is unavailable".into()))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn sync_event_pending_baseline(&self, conn: &Connection, event_id: i64) -> Result<bool, DatastoreError> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_journal_state WHERE id = 1 AND active = 1 AND baseline_complete = 0 AND key_epoch = (SELECT key_epoch FROM sync_key_material WHERE id = 1) AND baseline_max_event_id >= ?1 AND baseline_cursor < ?1)",
            [event_id],
            |row| row.get(0),
        ).map_err(|_| DatastoreError::InternalError("Sync baseline progress is unavailable".into()))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn local_sync_writer(&self, conn: &Connection) -> Result<([u8; 16], u64), DatastoreError> {
        let identity = self.get_sync_device_identity(conn)?
            .ok_or_else(|| DatastoreError::InternalError("Create a local sync identity before preparing sync".into()))?;
        let material = self.get_sync_key_material(conn)?
            .ok_or_else(|| DatastoreError::InternalError("Pair a device before preparing sync".into()))?;
        Ok((*identity.device_id(), material.key_epoch()))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn ensure_local_sync_bucket(
        &self,
        conn: &Connection,
        local_bucket_id: &str,
    ) -> Result<([u8; 16], SyncBucketDescriptorV1), DatastoreError> {
        let bucket = self.get_bucket(local_bucket_id)?;
        let current_descriptor = SyncBucketDescriptorV1 {
            bucket_type: bucket._type,
            client: bucket.client,
            data: bucket.data.into_iter().collect(),
        };
        current_descriptor.validate()
            .map_err(|_| DatastoreError::InvalidImport("Bucket metadata is too large for E2EE sync".into()))?;
        if let Some((sync_bucket_id, descriptor_json)) = conn.query_row(
            "SELECT sync_bucket_id,descriptor_json FROM sync_bucket_mappings WHERE local_bucket_id = ?1",
            [local_bucket_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Sync bucket mapping is unavailable".into()))? {
            let sync_bucket_id = sync_bucket_id.try_into()
                .map_err(|_| DatastoreError::InternalError("Stored sync bucket mapping is invalid".into()))?;
            let descriptor: SyncBucketDescriptorV1 = serde_json::from_str(&descriptor_json)
                .map_err(|_| DatastoreError::InternalError("Stored sync bucket descriptor is invalid".into()))?;
            descriptor.validate().map_err(|_| DatastoreError::InternalError("Stored sync bucket descriptor is invalid".into()))?;
            if descriptor != current_descriptor {
                return Err(DatastoreError::InternalError("Sync bucket metadata is immutable in V1".into()));
            }
            return Ok((sync_bucket_id, descriptor));
        }
        let mut sync_bucket_id = [0u8; 16];
        SystemRandom::new().fill(&mut sync_bucket_id)
            .map_err(|_| DatastoreError::InternalError("Secure randomness is required for sync bucket IDs".into()))?;
        let descriptor_json = serde_json::to_string(&current_descriptor)
            .map_err(|_| DatastoreError::InternalError("Sync bucket descriptor could not be encoded".into()))?;
        conn.execute(
            "INSERT INTO sync_bucket_mappings(sync_bucket_id,local_bucket_id,descriptor_json) VALUES (?1,?2,?3)",
            params![&sync_bucket_id[..], local_bucket_id, descriptor_json],
        ).map_err(|_| DatastoreError::InternalError("Sync bucket mapping could not be stored".into()))?;
        Ok((sync_bucket_id, current_descriptor))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn ensure_remote_sync_bucket(
        &mut self,
        conn: &Connection,
        sync_bucket_id: &[u8; 16],
        descriptor: &SyncBucketDescriptorV1,
        create_bucket: bool,
    ) -> Result<String, DatastoreError> {
        descriptor.validate().map_err(|_| DatastoreError::InternalError("Remote sync bucket descriptor is invalid".into()))?;
        if let Some((local_bucket_id, descriptor_json)) = conn.query_row(
            "SELECT local_bucket_id,descriptor_json FROM sync_bucket_mappings WHERE sync_bucket_id = ?1",
            [&sync_bucket_id[..]],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Sync bucket mapping is unavailable".into()))? {
            let stored: SyncBucketDescriptorV1 = serde_json::from_str(&descriptor_json)
                .map_err(|_| DatastoreError::InternalError("Stored sync bucket descriptor is invalid".into()))?;
            if stored != *descriptor {
                return Err(DatastoreError::InternalError("A sync bucket ID was reused with different metadata".into()));
            }
            if create_bucket && !self.buckets_cache.contains_key(&local_bucket_id) {
                self.create_bucket(conn, Bucket {
                    bid: None,
                    id: local_bucket_id.clone(),
                    _type: descriptor.bucket_type.clone(),
                    client: descriptor.client.clone(),
                    hostname: "synced".into(),
                    created: None,
                    data: descriptor.data.clone().into_iter().collect(),
                    metadata: BucketMetadata::default(),
                    events: None,
                    last_updated: None,
                })?;
            }
            return Ok(local_bucket_id);
        }
        let local_bucket_id = format!("aw-sync-{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sync_bucket_id));
        if self.buckets_cache.contains_key(&local_bucket_id) {
            return Err(DatastoreError::InternalError("Remote sync bucket ID collides with a local bucket".into()));
        }
        if create_bucket {
            self.create_bucket(conn, Bucket {
                bid: None,
                id: local_bucket_id.clone(),
                _type: descriptor.bucket_type.clone(),
                client: descriptor.client.clone(),
                hostname: "synced".into(),
                created: None,
                data: descriptor.data.clone().into_iter().collect(),
                metadata: BucketMetadata::default(),
                events: None,
                last_updated: None,
            })?;
        }
        let descriptor_json = serde_json::to_string(descriptor)
            .map_err(|_| DatastoreError::InternalError("Sync bucket descriptor could not be encoded".into()))?;
        conn.execute(
            "INSERT INTO sync_bucket_mappings(sync_bucket_id,local_bucket_id,descriptor_json) VALUES (?1,?2,?3)",
            params![&sync_bucket_id[..], &local_bucket_id, descriptor_json],
        ).map_err(|_| DatastoreError::InternalError("Sync bucket mapping could not be stored".into()))?;
        Ok(local_bucket_id)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn ensure_local_sync_event_mapping(
        &self,
        conn: &Connection,
        device_id: &[u8; 16],
        local_bucket_id: &str,
        local_event_id: i64,
        sync_bucket_id: &[u8; 16],
    ) -> Result<([u8; 16], u64), DatastoreError> {
        let local_event_id_u64 = u64::try_from(local_event_id)
            .ok().filter(|id| *id > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid local sync event ID".into()))?;
        let existing = conn.query_row(
            "SELECT origin_device_id,origin_event_id,sync_bucket_id FROM sync_event_mappings WHERE local_bucket_id = ?1 AND local_event_id = ?2",
            params![local_bucket_id, local_event_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Sync event mapping is unavailable".into()))?;
        if let Some((origin_device, origin_event, stored_bucket)) = existing {
            let origin_device: [u8; 16] = origin_device.try_into()
                .map_err(|_| DatastoreError::InternalError("Stored sync event mapping is invalid".into()))?;
            let stored_bucket: [u8; 16] = stored_bucket.try_into()
                .map_err(|_| DatastoreError::InternalError("Stored sync event mapping is invalid".into()))?;
            if stored_bucket != *sync_bucket_id {
                return Err(DatastoreError::InternalError("A sync event mapping changed bucket identity".into()));
            }
            let origin_event = u64::try_from(origin_event)
                .map_err(|_| DatastoreError::InternalError("Stored sync event mapping is invalid".into()))?;
            conn.execute(
                "UPDATE sync_event_mappings SET deleted = 0 WHERE origin_device_id = ?1 AND origin_event_id = ?2",
                params![&origin_device[..], origin_event as i64],
            ).map_err(|_| DatastoreError::InternalError("Sync event mapping could not be updated".into()))?;
            return Ok((origin_device, origin_event));
        }
        conn.execute(
            "INSERT INTO sync_event_mappings(origin_device_id,origin_event_id,sync_bucket_id,local_bucket_id,local_event_id,deleted) VALUES (?1,?2,?3,?4,?5,0)",
            params![&device_id[..], local_event_id as i64, &sync_bucket_id[..], local_bucket_id, local_event_id],
        ).map_err(|_| DatastoreError::InternalError("Sync event mapping could not be stored".into()))?;
        Ok((*device_id, local_event_id_u64))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn store_local_sync_operation(
        &self,
        conn: &Connection,
        device_id: [u8; 16],
        key_epoch: u64,
        operation: &SyncOperationV1,
    ) -> Result<(), DatastoreError> {
        let operation_json = serde_json::to_string(operation)
            .map_err(|_| DatastoreError::InternalError("Sync operation could not be encoded".into()))?;
        let hash = digest(&SHA256, operation_json.as_bytes());
        let content_hash: [u8; 32] = hash.as_ref().try_into()
            .map_err(|_| DatastoreError::InternalError("Sync operation hash is invalid".into()))?;
        self.put_sync_operation(conn, &SyncStoredOperationV1 {
            device_id,
            counter: operation.counter,
            key_epoch,
            operation_json,
            content_hash,
        })?;
        Ok(())
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn record_local_upsert(&self, conn: &Connection, bucket_id: &str, event: &Event) -> Result<(), DatastoreError> {
        if !self.sync_journal_active(conn)? { return Ok(()); }
        let (device_id, key_epoch) = self.local_sync_writer(conn)?;
        let local_event_id = event.id.ok_or_else(|| DatastoreError::InternalError("Stored event has no local ID".into()))?;
        let (sync_bucket_id, descriptor) = self.ensure_local_sync_bucket(conn, bucket_id)?;
        let (origin_device_id, origin_event_id) = self.ensure_local_sync_event_mapping(
            conn, &device_id, bucket_id, local_event_id, &sync_bucket_id,
        )?;
        let counter = self.next_sync_operation_counter(conn, &device_id)?;
        let mut operation = create_event_upsert(device_id, counter, sync_bucket_id, descriptor, event)
            .map_err(|_| DatastoreError::InvalidImport("Event cannot be represented by the sync operation contract".into()))?;
        operation.origin_device_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(origin_device_id);
        operation.local_event_id = Some(origin_event_id);
        operation.validate()
            .map_err(|_| DatastoreError::InvalidImport("Event cannot be represented by the sync operation contract".into()))?;
        self.store_local_sync_operation(conn, device_id, key_epoch, &operation)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn record_local_correction(
        &self,
        conn: &Connection,
        bucket_id: &str,
        previous: &Event,
        corrected: &Event,
    ) -> Result<(), DatastoreError> {
        if !self.sync_journal_active(conn)? { return Ok(()); }
        let (device_id, key_epoch) = self.local_sync_writer(conn)?;
        let local_event_id = corrected.id.ok_or_else(|| DatastoreError::InvalidCorrection("An event ID is required".into()))?;
        if self.sync_event_pending_baseline(conn, local_event_id)? {
            return self.record_local_upsert(conn, bucket_id, corrected);
        }
        let (sync_bucket_id, _) = self.ensure_local_sync_bucket(conn, bucket_id)?;
        let (origin_device, origin_event) = self.ensure_local_sync_event_mapping(conn, &device_id, bucket_id, local_event_id, &sync_bucket_id)?;
        let mut fields = BTreeMap::new();
        if previous.timestamp != corrected.timestamp {
            fields.insert("timestamp".into(), serde_json::json!(corrected.timestamp.to_rfc3339()));
        }
        if previous.duration != corrected.duration {
            let duration_ns = corrected.duration.num_nanoseconds()
                .ok_or_else(|| DatastoreError::InvalidCorrection("Event duration is out of range".into()))?;
            fields.insert("duration_ns".into(), serde_json::json!(duration_ns));
        }
        for key in previous.data.keys().chain(corrected.data.keys()).collect::<BTreeSet<_>>() {
            if previous.data.get(key) != corrected.data.get(key) {
                fields.insert(encode_sync_data_field_v1(key), corrected.data.get(key).cloned().unwrap_or(Value::Null));
            }
        }
        if fields.is_empty() { return Ok(()); }
        let counter = self.next_sync_operation_counter(conn, &device_id)?;
        let operation = create_event_correction(device_id, counter, origin_device, origin_event, sync_bucket_id, fields)
            .map_err(|_| DatastoreError::InvalidCorrection("Correction cannot be represented by the sync operation contract".into()))?;
        self.store_local_sync_operation(conn, device_id, key_epoch, &operation)
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn record_local_tombstone(&self, conn: &Connection, bucket_id: &str, event: &Event) -> Result<(), DatastoreError> {
        if !self.sync_journal_active(conn)? { return Ok(()); }
        let (device_id, key_epoch) = self.local_sync_writer(conn)?;
        let local_event_id = event.id.ok_or_else(|| DatastoreError::InternalError("Deleted event has no local ID".into()))?;
        let (sync_bucket_id, _) = self.ensure_local_sync_bucket(conn, bucket_id)?;
        let (origin_device, origin_event) = self.ensure_local_sync_event_mapping(conn, &device_id, bucket_id, local_event_id, &sync_bucket_id)?;
        let counter = self.next_sync_operation_counter(conn, &device_id)?;
        let operation = create_event_tombstone(device_id, counter, origin_device, origin_event, sync_bucket_id)
            .map_err(|_| DatastoreError::InternalError("Tombstone cannot be represented by the sync operation contract".into()))?;
        self.store_local_sync_operation(conn, device_id, key_epoch, &operation)?;
        conn.execute(
            "UPDATE sync_event_mappings SET deleted = 1 WHERE origin_device_id = ?1 AND origin_event_id = ?2",
            params![&origin_device[..], origin_event as i64],
        ).map_err(|_| DatastoreError::InternalError("Sync tombstone state could not be stored".into()))?;
        self.record_sync_tombstone_ack(
            conn,
            &origin_device,
            origin_event,
            counter,
            &device_id,
            &Utc::now().to_rfc3339(),
        )?;
        Ok(())
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn begin_sync_baseline(&self, conn: &Connection) -> Result<SyncBaselineProgressV1, DatastoreError> {
        let (_, key_epoch) = self.local_sync_writer(conn)?;
        let key_epoch_db = i64::try_from(key_epoch)
            .ok().filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync baseline epoch".into()))?;
        with_savepoint(conn, "sync_baseline_begin", || {
            let existing = conn.query_row(
                "SELECT active,key_epoch,baseline_max_event_id,baseline_cursor,baseline_complete FROM sync_journal_state WHERE id = 1",
                [],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, bool>(4)?)),
            ).optional().map_err(|_| DatastoreError::InternalError("Sync baseline state is unavailable".into()))?;
            if let Some((active, stored_epoch, watermark, cursor, complete)) = existing {
                if stored_epoch != key_epoch_db {
                    let watermark: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |row| row.get(0))
                        .map_err(|_| DatastoreError::InternalError("Sync baseline watermark is unavailable".into()))?;
                    let complete = watermark == 0;
                    conn.execute(
                        "UPDATE sync_journal_state SET active = 1,key_epoch = ?1,baseline_max_event_id = ?2,baseline_cursor = 0,baseline_complete = ?3 WHERE id = 1",
                        params![key_epoch_db, watermark, complete],
                    )
                    .map_err(|_| DatastoreError::InternalError("Sync baseline could not restart for the new key epoch".into()))?;
                return Ok(SyncBaselineProgressV1 {
                    key_epoch,
                    baseline_max_event_id: u64::try_from(watermark).map_err(|_| DatastoreError::InternalError("Sync baseline watermark is invalid".into()))?,
                        baseline_cursor: 0,
                        complete,
                    });
                }
                if !active {
                    conn.execute("UPDATE sync_journal_state SET active = 1 WHERE id = 1", [])
                        .map_err(|_| DatastoreError::InternalError("Sync baseline could not resume".into()))?;
                }
                return Ok(SyncBaselineProgressV1 {
                    key_epoch,
                    baseline_max_event_id: u64::try_from(watermark).map_err(|_| DatastoreError::InternalError("Stored sync baseline is invalid".into()))?,
                    baseline_cursor: u64::try_from(cursor).map_err(|_| DatastoreError::InternalError("Stored sync baseline is invalid".into()))?,
                    complete,
                });
            }
            let watermark: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |row| row.get(0))
                .map_err(|_| DatastoreError::InternalError("Sync baseline watermark is unavailable".into()))?;
            let complete = watermark == 0;
            conn.execute(
                "INSERT INTO sync_journal_state(id,active,key_epoch,baseline_max_event_id,baseline_cursor,baseline_complete) VALUES (1,1,?1,?2,0,?3)",
                params![key_epoch_db, watermark, complete],
            ).map_err(|_| DatastoreError::InternalError("Sync baseline could not start".into()))?;
            Ok(SyncBaselineProgressV1 {
                key_epoch,
                baseline_max_event_id: u64::try_from(watermark).map_err(|_| DatastoreError::InternalError("Sync baseline watermark is invalid".into()))?,
                baseline_cursor: 0,
                complete,
            })
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_baseline_progress(
        &self,
        conn: &Connection,
    ) -> Result<Option<SyncBaselineProgressV1>, DatastoreError> {
        let Some(material) = self.get_sync_key_material(conn)? else { return Ok(None); };
        let current_epoch = material.key_epoch();
        let current_epoch_db = i64::try_from(current_epoch)
            .map_err(|_| DatastoreError::InternalError("Invalid sync baseline epoch".into()))?;
        let stored = conn.query_row(
            "SELECT active,key_epoch,baseline_max_event_id,baseline_cursor,baseline_complete FROM sync_journal_state WHERE id = 1",
            [],
            |row| Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, bool>(4)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Sync baseline progress is unavailable".into()))?;
        let Some((active, stored_epoch, watermark, cursor, complete)) = stored else { return Ok(None); };
        if stored_epoch != current_epoch_db {
            let watermark: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |row| row.get(0))
                .map_err(|_| DatastoreError::InternalError("Sync baseline watermark is unavailable".into()))?;
            return Ok(Some(SyncBaselineProgressV1 {
                key_epoch: current_epoch,
                baseline_max_event_id: u64::try_from(watermark).map_err(|_| DatastoreError::InternalError("Sync baseline watermark is invalid".into()))?,
                baseline_cursor: 0,
                complete: watermark == 0,
            }));
        }
        Ok(Some(SyncBaselineProgressV1 {
            key_epoch: current_epoch,
            baseline_max_event_id: u64::try_from(watermark).map_err(|_| DatastoreError::InternalError("Stored sync baseline is invalid".into()))?,
            baseline_cursor: u64::try_from(cursor).map_err(|_| DatastoreError::InternalError("Stored sync baseline is invalid".into()))?,
            complete: active && complete,
        }))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn process_sync_baseline_batch(
        &mut self,
        conn: &Connection,
        limit: usize,
    ) -> Result<SyncBaselineProgressV1, DatastoreError> {
        let (_, key_epoch) = self.local_sync_writer(conn)?;
        let key_epoch_db = i64::try_from(key_epoch)
            .map_err(|_| DatastoreError::InternalError("Invalid sync baseline epoch".into()))?;
        let limit = limit.clamp(1, 256);
        with_savepoint(conn, "sync_baseline_batch", || {
            let (active, baseline_epoch, watermark, cursor, complete): (bool, i64, i64, i64, bool) = conn.query_row(
                "SELECT active,key_epoch,baseline_max_event_id,baseline_cursor,baseline_complete FROM sync_journal_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            ).map_err(|_| DatastoreError::InternalError("Sync baseline has not started".into()))?;
            if !active { return Err(DatastoreError::InternalError("Sync baseline is inactive".into())); }
            if baseline_epoch != key_epoch_db {
                return Err(DatastoreError::InternalError("Start a new sync baseline for the current key epoch".into()));
            }
            if complete {
                return Ok(SyncBaselineProgressV1 {
                    key_epoch,
                    baseline_max_event_id: watermark as u64,
                    baseline_cursor: cursor as u64,
                    complete: true,
                });
            }
            let rows = {
                let mut statement = conn.prepare_cached(
                    "SELECT e.id,b.name FROM events e JOIN buckets b ON b.id = e.bucketrow WHERE e.id > ?1 AND e.id <= ?2 ORDER BY e.id LIMIT ?3",
                ).map_err(|_| DatastoreError::InternalError("Sync baseline query is unavailable".into()))?;
                let rows = statement.query_map(params![cursor, watermark, limit as i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                }).map_err(|_| DatastoreError::InternalError("Sync baseline query failed".into()))?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|_| DatastoreError::InternalError("Sync baseline event is invalid".into()))?
            };
            for (event_id, bucket_id) in &rows {
                let event = self.get_event(conn, bucket_id, *event_id)?;
                self.record_local_upsert(conn, bucket_id, &event)?;
            }
            let next_cursor = rows.last().map(|(id, _)| *id).unwrap_or(watermark);
            let more: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE id > ?1 AND id <= ?2)",
                params![next_cursor, watermark],
                |row| row.get(0),
            ).map_err(|_| DatastoreError::InternalError("Sync baseline progress is unavailable".into()))?;
            let complete = !more;
            let next_cursor = if complete { watermark } else { next_cursor };
            conn.execute(
                "UPDATE sync_journal_state SET baseline_cursor = ?1,baseline_complete = ?2 WHERE id = 1",
                params![next_cursor, complete],
            ).map_err(|_| DatastoreError::InternalError("Sync baseline progress could not be stored".into()))?;
            Ok(SyncBaselineProgressV1 {
                key_epoch,
                baseline_max_event_id: watermark as u64,
                baseline_cursor: next_cursor as u64,
                complete,
            })
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn apply_sync_operations(
        &mut self,
        conn: &Connection,
        batch: &SyncApplyBatchV1,
    ) -> Result<SyncHeadCommitV1, DatastoreError> {
        let material = self.get_sync_key_material(conn)?
            .ok_or_else(|| DatastoreError::InternalError("Sync keys are unavailable".into()))?;
        let manifest = &batch.manifest;
        let writer_device_id: [u8; 16] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&manifest.writer_device_id)
            .map_err(|_| DatastoreError::InternalError("Remote sync writer is invalid".into()))?
            .try_into().map_err(|_| DatastoreError::InternalError("Remote sync writer is invalid".into()))?;
        let key_epoch = manifest.key_epoch;
        if material.key_epoch() != key_epoch || manifest.operations.len() > 10_000 {
            return Err(DatastoreError::InternalError("Remote sync batch is invalid".into()));
        }
        let trusted = conn.query_row(
            "SELECT x25519_public_key,ed25519_public_key FROM sync_trusted_devices WHERE device_id = ?1 AND key_epoch = ?2 AND revoked_at IS NULL",
            params![&writer_device_id[..], i64::try_from(key_epoch).map_err(|_| DatastoreError::InternalError("Invalid sync epoch".into()))?],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Could not verify the sync writer".into()))?;
        let Some((x25519_public_key, Some(ed25519_public_key))) = trusted else {
            return Err(DatastoreError::InternalError("Sync writer is not trusted in the current epoch".into()));
        };
        let writer_identity = DevicePublicIdentityV1 {
            schema_version: 1,
            device_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(writer_device_id),
            x25519_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x25519_public_key),
            ed25519_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ed25519_public_key),
        };
        manifest.verify_signature(&writer_identity, material.vault_id())
            .map_err(|_| DatastoreError::InternalError("Remote sync manifest signature is invalid".into()))?;

        let vault_id = *material.vault_id();
        let next_head_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&manifest.head_hash)
            .map_err(|_| DatastoreError::InternalError("Remote sync manifest hash is invalid".into()))?;
        let next_head_hash: [u8; 32] = next_head_hash.try_into()
            .map_err(|_| DatastoreError::InternalError("Remote sync manifest hash is invalid".into()))?;
        let next_head = SyncManifestHeadV1::new(manifest.revision, next_head_hash);
        let result = with_savepoint(conn, "sync_remote_apply", || {
            let current = self.get_sync_manifest_head(conn, &vault_id, key_epoch, &writer_device_id)?
                .unwrap_or_else(SyncManifestHeadV1::genesis);
            if current == next_head { return Ok(SyncHeadCommitV1::Duplicate); }
            match manifest.advance(&SyncHeadV1::new(current.revision, current.head_hash)) {
                Ok(ManifestDecisionV1::Advanced(_)) => (),
                _ => return Err(DatastoreError::InternalError("Remote sync manifest does not continue the trusted stream".into())),
            }

            for operation in &manifest.operations {
                operation.validate().map_err(|_| DatastoreError::InternalError("Remote sync operation is invalid".into()))?;
                let actor = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&operation.device_id)
                    .map_err(|_| DatastoreError::InternalError("Remote sync writer is invalid".into()))?;
                if actor.as_slice() != &writer_device_id[..] {
                    return Err(DatastoreError::InternalError("A sync device cannot write another device's operation stream".into()));
                }
                let last_counter: i64 = conn.query_row(
                    "SELECT COALESCE(MAX(value),0) FROM (SELECT last_counter AS value FROM sync_device_counters WHERE device_id = ?1 UNION ALL SELECT MAX(counter) AS value FROM sync_operations WHERE device_id = ?1)",
                    [&writer_device_id[..]],
                    |row| row.get(0),
                ).map_err(|_| DatastoreError::InternalError("Remote sync operation counter is unavailable".into()))?;
                let operation_already_stored = conn.query_row(
                    "SELECT 1 FROM sync_operations WHERE device_id = ?1 AND counter = ?2 AND key_epoch = ?3",
                    params![&writer_device_id[..], i64::try_from(operation.counter)
                        .map_err(|_| DatastoreError::InternalError("Remote sync operation counter is invalid".into()))?,
                        i64::try_from(key_epoch).map_err(|_| DatastoreError::InternalError("Remote sync operation epoch is invalid".into()))?],
                    |_| Ok(()),
                ).optional().map_err(|_| DatastoreError::InternalError("Remote sync operation history is unavailable".into()))?.is_some();
                if operation.counter <= last_counter as u64 && !operation_already_stored {
                    return Err(DatastoreError::InternalError("Remote sync operation counter moved backwards".into()));
                }
                self.store_local_sync_operation(conn, writer_device_id, key_epoch, operation)?;
                let observed_counter = i64::try_from(operation.counter)
                    .map_err(|_| DatastoreError::InternalError("Remote sync operation counter is invalid".into()))?;
                conn.execute(
                    "INSERT INTO sync_device_counters(device_id,last_counter) VALUES (?1,?2) ON CONFLICT(device_id) DO UPDATE SET last_counter = MAX(sync_device_counters.last_counter,excluded.last_counter)",
                    params![&writer_device_id[..], observed_counter],
                ).map_err(|_| DatastoreError::InternalError("Remote sync operation counter could not be stored".into()))?;
            }

            let operations = self.all_sync_operations_for_epoch(conn, key_epoch)?;
            let merged = merge_operations(&[], &operations)
                .map_err(|_| DatastoreError::InternalError("Stored sync operations could not be merged".into()))?;
            let mut known_tombstones = BTreeSet::new();
            for operation in &operations {
                if operation.kind != SyncOperationKindV1::Tombstone { continue; }
                let origin: [u8; 16] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&operation.origin_device_id)
                    .map_err(|_| DatastoreError::InternalError("Stored tombstone identity is invalid".into()))?
                    .try_into().map_err(|_| DatastoreError::InternalError("Stored tombstone identity is invalid".into()))?;
                let event_id = operation.local_event_id
                    .ok_or_else(|| DatastoreError::InternalError("Stored tombstone has no event ID".into()))?;
                known_tombstones.insert((origin, event_id, operation.counter));
            }
            let acked_at = Utc::now().to_rfc3339();
            for acknowledgement in &manifest.tombstone_acknowledgements {
                let origin: [u8; 16] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&acknowledgement.origin_device_id)
                    .map_err(|_| DatastoreError::InternalError("Remote tombstone acknowledgement is invalid".into()))?
                    .try_into().map_err(|_| DatastoreError::InternalError("Remote tombstone acknowledgement is invalid".into()))?;
                if !known_tombstones.contains(&(origin, acknowledgement.local_event_id, acknowledgement.tombstone_counter)) {
                    return Err(DatastoreError::InternalError("Remote device acknowledged an unknown tombstone".into()));
                }
                self.record_sync_tombstone_ack(
                    conn, &origin, acknowledgement.local_event_id, acknowledgement.tombstone_counter,
                    &writer_device_id, &acked_at,
                )?;
            }
            let local_device_id = self.get_sync_device_identity(conn)?
                .ok_or_else(|| DatastoreError::InternalError("Local sync identity is unavailable".into()))?
                .device_id().to_owned();
            let mut seen = BTreeSet::new();
            for event in &merged.events {
                let origin = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&event.origin_device_id)
                    .map_err(|_| DatastoreError::InternalError("Remote sync event origin is invalid".into()))?;
                let origin: [u8; 16] = origin.try_into()
                    .map_err(|_| DatastoreError::InternalError("Remote sync event origin is invalid".into()))?;
                let sync_bucket = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&event.sync_bucket_id)
                    .map_err(|_| DatastoreError::InternalError("Remote sync bucket ID is invalid".into()))?;
                let sync_bucket: [u8; 16] = sync_bucket.try_into()
                    .map_err(|_| DatastoreError::InternalError("Remote sync bucket ID is invalid".into()))?;
                let origin_event_id = i64::try_from(event.local_event_id)
                    .ok().filter(|id| *id > 0)
                    .ok_or_else(|| DatastoreError::InternalError("Remote sync event ID is invalid".into()))?;
                if !seen.insert((origin, origin_event_id)) {
                    return Err(DatastoreError::InternalError("Remote sync batch repeats an event identity".into()));
                }

                let stored = conn.query_row(
                    "SELECT sync_bucket_id,local_bucket_id,local_event_id,deleted FROM sync_event_mappings WHERE origin_device_id = ?1 AND origin_event_id = ?2",
                    params![&origin[..], origin_event_id],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, bool>(3)?)),
                ).optional().map_err(|_| DatastoreError::InternalError("Could not inspect remote event mapping".into()))?;
                if stored.as_ref().is_some_and(|(mapped_bucket, _, _, _)| mapped_bucket.as_slice() != &sync_bucket[..]) {
                    return Err(DatastoreError::InternalError("A remote event changed its immutable bucket identity".into()));
                }

                let stored_descriptor = conn.query_row(
                    "SELECT descriptor_json FROM sync_bucket_mappings WHERE sync_bucket_id = ?1",
                    [&sync_bucket[..]],
                    |row| row.get::<_, String>(0),
                ).optional().map_err(|_| DatastoreError::InternalError("Could not inspect remote bucket metadata".into()))?
                    .map(|json| serde_json::from_str::<SyncBucketDescriptorV1>(&json)
                        .map_err(|_| DatastoreError::InternalError("Stored sync bucket descriptor is invalid".into())))
                    .transpose()?;
                let incoming_descriptor = manifest.operations.iter().filter_map(|operation| {
                    (operation.sync_bucket_id.as_deref() == Some(event.sync_bucket_id.as_str()))
                        .then_some(operation.bucket_descriptor.as_ref()).flatten()
                }).next().cloned();
                if manifest.operations.iter().filter_map(|operation| operation.bucket_descriptor.as_ref()
                    .filter(|_| operation.sync_bucket_id.as_deref() == Some(event.sync_bucket_id.as_str())))
                    .any(|descriptor| incoming_descriptor.as_ref() != Some(descriptor))
                {
                    return Err(DatastoreError::InternalError("Remote manifest forks bucket metadata".into()));
                }
                if stored_descriptor.as_ref().is_some_and(|stored| incoming_descriptor.as_ref().is_some_and(|incoming| stored != incoming)) {
                    return Err(DatastoreError::InternalError("A sync bucket ID was reused with different metadata".into()));
                }
                let descriptor = incoming_descriptor.or(stored_descriptor);
                let local_bucket_id = if event.deleted {
                    if let Some(descriptor) = descriptor.as_ref() {
                        self.ensure_remote_sync_bucket(conn, &sync_bucket, descriptor, false)?
                    } else if let Some((_, local_bucket_id, _, _)) = stored.as_ref() {
                        local_bucket_id.clone()
                    } else {
                        let candidate = format!("aw-sync-{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sync_bucket));
                        if self.buckets_cache.contains_key(&candidate) {
                            return Err(DatastoreError::InternalError("Remote sync bucket ID collides with a local bucket".into()));
                        }
                        candidate
                    }
                } else {
                    let descriptor = descriptor.as_ref()
                        .ok_or_else(|| DatastoreError::InternalError("Remote event has no authenticated bucket descriptor".into()))?;
                    self.ensure_remote_sync_bucket(conn, &sync_bucket, descriptor, true)?
                };
                if stored.as_ref().is_some_and(|(_, mapped_local_bucket, _, _)| mapped_local_bucket != &local_bucket_id) {
                    return Err(DatastoreError::InternalError("A remote event changed its local bucket mapping".into()));
                }
                let mapped_event_id = stored.as_ref().and_then(|(_, _, local_id, _)| *local_id);

                if event.deleted {
                    for (_, _, tombstone_counter) in known_tombstones.range(
                        (origin, event.local_event_id, 0)..=(origin, event.local_event_id, u64::MAX),
                    ) {
                        self.record_sync_tombstone_ack(
                            conn, &origin, event.local_event_id, *tombstone_counter,
                            &local_device_id, &acked_at,
                        )?;
                    }
                    if let Some(local_id) = mapped_event_id {
                        conn.execute("DELETE FROM event_corrections WHERE bucketrow = (SELECT id FROM buckets WHERE name = ?1) AND event_id = ?2", params![&local_bucket_id, local_id])
                            .map_err(|_| DatastoreError::InternalError("Remote event corrections could not be removed".into()))?;
                        conn.execute("DELETE FROM events WHERE bucketrow = (SELECT id FROM buckets WHERE name = ?1) AND id = ?2", params![&local_bucket_id, local_id])
                            .map_err(|_| DatastoreError::InternalError("Remote event could not be deleted".into()))?;
                    }
                    if stored.is_some() {
                        conn.execute("UPDATE sync_event_mappings SET deleted = 1 WHERE origin_device_id = ?1 AND origin_event_id = ?2", params![&origin[..], origin_event_id])
                            .map_err(|_| DatastoreError::InternalError("Remote tombstone mapping could not be stored".into()))?;
                    } else {
                        conn.execute(
                            "INSERT INTO sync_event_mappings(origin_device_id,origin_event_id,sync_bucket_id,local_bucket_id,local_event_id,deleted) VALUES (?1,?2,?3,?4,NULL,1)",
                            params![&origin[..], origin_event_id, &sync_bucket[..], &local_bucket_id],
                        ).map_err(|_| DatastoreError::InternalError("Remote tombstone mapping could not be stored".into()))?;
                    }
                    continue;
                }

                let timestamp = event.fields.get("timestamp").and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .map(|value| value.with_timezone(&Utc))
                    .ok_or_else(|| DatastoreError::InternalError("Remote sync event timestamp is invalid".into()))?;
                let duration_ns = event.fields.get("duration_ns").and_then(Value::as_i64)
                    .filter(|duration| *duration >= 0)
                    .ok_or_else(|| DatastoreError::InternalError("Remote sync event duration is invalid".into()))?;
                let mut data = serde_json::Map::new();
                for (field, value) in &event.fields {
                    if matches!(field.as_str(), "timestamp" | "duration_ns") { continue; }
                    let key = if field.starts_with("data:") {
                        decode_sync_data_field_v1(field)
                            .ok_or_else(|| DatastoreError::InternalError("Remote sync data field is invalid".into()))?
                    } else {
                        field.clone()
                    };
                    if value.is_null() { data.remove(&key); }
                    else { data.insert(key, value.clone()); }
                }
                let mut projected = Event {
                    id: mapped_event_id,
                    timestamp,
                    duration: Duration::nanoseconds(duration_ns),
                    data,
                };
                let inserted = self.insert_events_inner(conn, &local_bucket_id, vec![projected.clone()], false)?;
                projected = inserted.into_iter().next()
                    .ok_or_else(|| DatastoreError::InternalError("Remote sync event was not applied".into()))?;
                let local_event_id = projected.id.ok_or_else(|| DatastoreError::InternalError("Remote sync event has no local ID".into()))?;
                if stored.is_some() {
                    conn.execute(
                        "UPDATE sync_event_mappings SET local_event_id = ?1,deleted = 0 WHERE origin_device_id = ?2 AND origin_event_id = ?3",
                        params![local_event_id, &origin[..], origin_event_id],
                    ).map_err(|_| DatastoreError::InternalError("Remote sync event mapping could not be updated".into()))?;
                } else {
                    conn.execute(
                        "INSERT INTO sync_event_mappings(origin_device_id,origin_event_id,sync_bucket_id,local_bucket_id,local_event_id,deleted) VALUES (?1,?2,?3,?4,?5,0)",
                        params![&origin[..], origin_event_id, &sync_bucket[..], &local_bucket_id, local_event_id],
                    ).map_err(|_| DatastoreError::InternalError("Remote sync event mapping could not be stored".into()))?;
                }
            }

            self.reload_buckets(conn)?;
            self.commit_sync_manifest_head(conn, &vault_id, key_epoch, &writer_device_id, current, next_head)
        });
        if result.is_err() { self.reload_buckets(conn)?; }
        result
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_device_identity(
        &self,
        conn: &Connection,
    ) -> Result<Option<SyncDeviceIdentity>, DatastoreError> {
        let stored = conn
            .query_row(
                "SELECT device_id, private_key, signing_seed FROM sync_device_identity WHERE id = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Option<Vec<u8>>>(2)?)),
            )
            .optional()
            .map_err(|_| DatastoreError::InternalError("Stored sync identity is unavailable".into()))?;
        let Some((device_id, private_key, signing_seed)) = stored else {
            return Ok(None);
        };
        let device_id = device_id
            .try_into()
            .map_err(|_| DatastoreError::InternalError("Stored sync identity is invalid".into()))?;
        let private_key = zeroize::Zeroizing::new(private_key);
        if private_key.len() != 32 {
            return Err(DatastoreError::InternalError("Stored sync identity is invalid".into()));
        }
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&private_key);
        let signing_seed = zeroize::Zeroizing::new(signing_seed
            .ok_or_else(|| DatastoreError::InternalError("Local sync identity needs signing-key repair".into()))?);
        if signing_seed.len() != 32 {
            return Err(DatastoreError::InternalError("Stored sync identity is invalid".into()));
        }
        let mut signing_secret = zeroize::Zeroizing::new([0u8; 32]);
        signing_secret.copy_from_slice(&signing_seed);
        Ok(Some(SyncDeviceIdentity::new(device_id, secret, signing_secret)))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_key_material(
        &self,
        conn: &Connection,
    ) -> Result<Option<crate::SyncKeyMaterial>, DatastoreError> {
        let stored = conn
            .query_row(
                "SELECT account_root_key, vault_id, key_epoch, wrapped_nonce, wrapped_ciphertext FROM sync_key_material WHERE id = 1",
                [],
                |row| Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                )),
            )
            .optional()
            .map_err(|_| DatastoreError::InternalError("Stored sync keys are unavailable".into()))?;
        let Some((root_key, vault_id, key_epoch, nonce, ciphertext)) = stored else {
            return Ok(None);
        };
        let root_key = zeroize::Zeroizing::new(root_key);
        if root_key.len() != 32 {
            return Err(DatastoreError::InternalError("Stored sync keys are invalid".into()));
        }
        let key_epoch = u64::try_from(key_epoch)
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Stored sync keys are invalid".into()))?;
        let mut root = zeroize::Zeroizing::new([0u8; 32]);
        root.copy_from_slice(&root_key);
        let vault_id = vault_id
            .try_into()
            .map_err(|_| DatastoreError::InternalError("Stored sync keys are invalid".into()))?;
        let nonce = nonce
            .try_into()
            .map_err(|_| DatastoreError::InternalError("Stored sync keys are invalid".into()))?;
        let ciphertext = ciphertext
            .try_into()
            .map_err(|_| DatastoreError::InternalError("Stored sync keys are invalid".into()))?;
        Ok(Some(crate::SyncKeyMaterial::new(root, vault_id, key_epoch, nonce, ciphertext)))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn install_sync_key_material(
        &self,
        conn: &Connection,
        material: &crate::SyncKeyMaterial,
    ) -> Result<(), DatastoreError> {
        with_savepoint(conn, "sync_key_material_install", || {
            self.insert_sync_key_material(conn, material)
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_snapshot(
        &self,
        conn: &Connection,
    ) -> Result<Option<crate::SyncSnapshotV1>, DatastoreError> {
        let snapshot_id = conn.query_row(
            "SELECT snapshot_id FROM sync_snapshot_current WHERE id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ).optional().map_err(|_| DatastoreError::InternalError("Stored sync snapshot is unavailable".into()))?;
        let Some(snapshot_id) = snapshot_id else { return Ok(None); };
        let snapshot_id: [u8; 16] = snapshot_id.try_into()
            .map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?;
        let mut statement = conn.prepare_cached(
            "SELECT chunk_index, object_id, vault_id, key_epoch, nonce, ciphertext FROM sync_snapshot_chunks WHERE snapshot_id = ?1 ORDER BY chunk_index",
        ).map_err(|_| DatastoreError::InternalError("Stored sync snapshot is unavailable".into()))?;
        let mut rows = statement.query([&snapshot_id[..]])
            .map_err(|_| DatastoreError::InternalError("Stored sync snapshot is unavailable".into()))?;
        let mut envelopes = Vec::new();
        while let Some(row) = rows.next().map_err(|_| DatastoreError::InternalError("Stored sync snapshot is unavailable".into()))? {
            let index: i64 = row.get(0).map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?;
            if index != envelopes.len() as i64 {
                return Err(DatastoreError::InternalError("Stored sync snapshot is incomplete".into()));
            }
            let envelope = aw_models::SyncEnvelopeV1 {
                schema_version: 1,
                object_id: row.get(1).map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?,
                vault_id: row.get(2).map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?,
                key_epoch: u64::try_from(row.get::<_, i64>(3).map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?)
                    .map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?,
                nonce: row.get(4).map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?,
                ciphertext: row.get(5).map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?,
            };
            envelope.validate().map_err(|_| DatastoreError::InternalError("Stored sync snapshot is invalid".into()))?;
            envelopes.push(envelope);
        }
        if envelopes.is_empty() {
            return Err(DatastoreError::InternalError("Stored sync snapshot is empty".into()));
        }
        Ok(Some(crate::SyncSnapshotV1::new(snapshot_id, envelopes)))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_recovery_state(
        &self,
        conn: &Connection,
        key_epoch: u64,
    ) -> Result<SyncRecoveryStateV1, DatastoreError> {
        let material = self.get_sync_key_material(conn)?
            .ok_or_else(|| DatastoreError::InternalError("Sync keys are unavailable".into()))?;
        if key_epoch == 0 { return Err(DatastoreError::InternalError("Invalid recovery key epoch".into())); }
        let key_epoch_db = i64::try_from(key_epoch).ok().filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid recovery key epoch".into()))?;
        let same_epoch = material.key_epoch() == key_epoch;
        let baseline_complete = if same_epoch {
            conn.query_row(
                "SELECT 1 FROM sync_journal_state WHERE id = 1 AND active = 1 AND key_epoch = ?1 AND baseline_complete = 1",
                [key_epoch_db],
                |_| Ok(()),
            ).optional().map_err(|_| DatastoreError::InternalError("Sync baseline state is unavailable".into()))?.is_some()
        } else { false };

        let bucket_mappings = {
            let mut statement = conn.prepare_cached(
                "SELECT sync_bucket_id,local_bucket_id,descriptor_json FROM sync_bucket_mappings ORDER BY sync_bucket_id LIMIT 100001",
            ).map_err(|_| DatastoreError::InternalError("Sync bucket mappings are unavailable".into()))?;
            let rows = statement.query_map([], |row| Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
            ))).map_err(|_| DatastoreError::InternalError("Sync bucket mappings are unavailable".into()))?;
            let rows = rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| DatastoreError::InternalError("Sync bucket mappings are invalid".into()))?;
            if rows.len() > 100_000 { return Err(DatastoreError::InternalError("Sync bucket mappings exceed the recovery limit".into())); }
            rows.into_iter().map(|(sync_bucket_id, local_bucket_id, descriptor_json)| {
                Ok(SyncRecoveryBucketMappingV1 {
                    sync_bucket_id: sync_bucket_id.try_into()
                        .map_err(|_| DatastoreError::InternalError("Sync bucket mapping is invalid".into()))?,
                    local_bucket_id,
                    descriptor: serde_json::from_str(&descriptor_json)
                        .map_err(|_| DatastoreError::InternalError("Sync bucket mapping is invalid".into()))?,
                })
            }).collect::<Result<Vec<_>, DatastoreError>>()?
        };
        let event_mappings = {
            let mut statement = conn.prepare_cached(
                "SELECT origin_device_id,origin_event_id,sync_bucket_id,local_bucket_id,local_event_id,deleted FROM sync_event_mappings ORDER BY origin_device_id,origin_event_id LIMIT 100001",
            ).map_err(|_| DatastoreError::InternalError("Sync event mappings are unavailable".into()))?;
            let rows = statement.query_map([], |row| Ok((
                row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, bool>(5)?,
            ))).map_err(|_| DatastoreError::InternalError("Sync event mappings are unavailable".into()))?;
            let rows = rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| DatastoreError::InternalError("Sync event mappings are invalid".into()))?;
            if rows.len() > 100_000 { return Err(DatastoreError::InternalError("Sync event mappings exceed the recovery limit".into())); }
            rows.into_iter().map(|(origin_device_id, origin_event_id, sync_bucket_id, local_bucket_id, local_event_id, deleted)| {
                Ok(SyncRecoveryEventMappingV1 {
                    origin_device_id: origin_device_id.try_into()
                        .map_err(|_| DatastoreError::InternalError("Sync event mapping is invalid".into()))?,
                    origin_event_id: u64::try_from(origin_event_id).ok().filter(|id| *id > 0)
                        .ok_or_else(|| DatastoreError::InternalError("Sync event mapping is invalid".into()))?,
                    sync_bucket_id: sync_bucket_id.try_into()
                        .map_err(|_| DatastoreError::InternalError("Sync event mapping is invalid".into()))?,
                    local_bucket_id,
                    local_event_id: local_event_id.map(|id| u64::try_from(id).ok().filter(|id| *id > 0)
                        .ok_or_else(|| DatastoreError::InternalError("Sync event mapping is invalid".into()))).transpose()?,
                    deleted,
                })
            }).collect::<Result<Vec<_>, DatastoreError>>()?
        };
        let counters = {
            let mut statement = conn.prepare_cached(
                "SELECT device_id,last_counter FROM sync_device_counters ORDER BY device_id LIMIT 100001",
            ).map_err(|_| DatastoreError::InternalError("Sync counters are unavailable".into()))?;
            let rows = statement.query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)))
                .map_err(|_| DatastoreError::InternalError("Sync counters are unavailable".into()))?;
            let rows = rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| DatastoreError::InternalError("Sync counters are invalid".into()))?;
            if rows.len() > 100_000 { return Err(DatastoreError::InternalError("Sync counters exceed the recovery limit".into())); }
            rows.into_iter().map(|(device_id, last_counter)| {
                Ok(SyncRecoveryCounterV1 {
                    device_id: device_id.try_into()
                        .map_err(|_| DatastoreError::InternalError("Sync counter is invalid".into()))?,
                    last_counter: u64::try_from(last_counter).ok().filter(|counter| *counter > 0)
                        .ok_or_else(|| DatastoreError::InternalError("Sync counter is invalid".into()))?,
                })
            }).collect::<Result<Vec<_>, DatastoreError>>()?
        };
        let (trusted_devices, operations, stream_heads, tombstone_acknowledgements) = if same_epoch {
            let trusted_devices = self.get_sync_trusted_devices(conn)?.into_iter()
                .filter(|device| device.key_epoch == key_epoch && device.revoked_at.is_none())
                .filter_map(|device| device.ed25519_public_key.map(|ed25519_public_key| SyncRecoveryTrustedDeviceV1 {
                    device_id: device.device_id,
                    x25519_public_key: device.x25519_public_key,
                    ed25519_public_key,
                    paired_at: device.paired_at,
                }))
                .collect::<Vec<_>>();
            let operations = if baseline_complete {
                let mut statement = conn.prepare_cached(
                    "SELECT device_id,counter,key_epoch,operation_json,content_hash FROM sync_operations WHERE key_epoch = ?1 ORDER BY device_id,counter LIMIT 100001",
                ).map_err(|_| DatastoreError::InternalError("Sync operations are unavailable".into()))?;
                let rows = statement.query_map([key_epoch_db], |row| Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?, row.get::<_, Vec<u8>>(4)?,
                ))).map_err(|_| DatastoreError::InternalError("Sync operations are unavailable".into()))?;
                let rows = rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|_| DatastoreError::InternalError("Sync operations are invalid".into()))?;
                if rows.len() > 100_000 { return Err(DatastoreError::InternalError("Sync operations exceed the recovery limit".into())); }
                rows.into_iter().map(|(device_id, counter, epoch, operation_json, content_hash)| {
                    Ok(SyncStoredOperationV1 {
                        device_id: device_id.try_into()
                            .map_err(|_| DatastoreError::InternalError("Sync operation is invalid".into()))?,
                        counter: u64::try_from(counter).ok().filter(|value| *value > 0)
                            .ok_or_else(|| DatastoreError::InternalError("Sync operation is invalid".into()))?,
                        key_epoch: u64::try_from(epoch).ok().filter(|value| *value > 0)
                            .ok_or_else(|| DatastoreError::InternalError("Sync operation is invalid".into()))?,
                        operation_json,
                        content_hash: content_hash.try_into()
                            .map_err(|_| DatastoreError::InternalError("Sync operation is invalid".into()))?,
                    })
                }).collect::<Result<Vec<_>, DatastoreError>>()?
            } else { Vec::new() };
            let stream_heads = if baseline_complete {
                let mut statement = conn.prepare_cached(
                    "SELECT device_id,revision,head_hash FROM sync_stream_heads WHERE vault_id = ?1 AND key_epoch = ?2 ORDER BY device_id LIMIT 100001",
                ).map_err(|_| DatastoreError::InternalError("Sync stream heads are unavailable".into()))?;
                let rows = statement.query_map(params![&material.vault_id()[..], key_epoch_db], |row| Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?,
                ))).map_err(|_| DatastoreError::InternalError("Sync stream heads are unavailable".into()))?;
                let rows = rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|_| DatastoreError::InternalError("Sync stream heads are invalid".into()))?;
                if rows.len() > 100_000 { return Err(DatastoreError::InternalError("Sync stream heads exceed the recovery limit".into())); }
                rows.into_iter().map(|(device_id, revision, head_hash)| {
                    Ok(SyncRecoveryStreamHeadV1 {
                        device_id: device_id.try_into()
                            .map_err(|_| DatastoreError::InternalError("Sync stream head is invalid".into()))?,
                        revision: u64::try_from(revision).ok().filter(|value| *value > 0)
                            .ok_or_else(|| DatastoreError::InternalError("Sync stream head is invalid".into()))?,
                        head_hash: head_hash.try_into()
                            .map_err(|_| DatastoreError::InternalError("Sync stream head is invalid".into()))?,
                    })
                }).collect::<Result<Vec<_>, DatastoreError>>()?
            } else { Vec::new() };
            let tombstone_acknowledgements = if baseline_complete {
                let mut statement = conn.prepare_cached(
                    "SELECT origin_device_id,local_event_id,tombstone_counter,device_id,acknowledged_at FROM sync_tombstone_acknowledgements ORDER BY origin_device_id,local_event_id,tombstone_counter,device_id LIMIT 100001",
                ).map_err(|_| DatastoreError::InternalError("Sync tombstone acknowledgements are unavailable".into()))?;
                let rows = statement.query_map([], |row| Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?, row.get::<_, String>(4)?,
                ))).map_err(|_| DatastoreError::InternalError("Sync tombstone acknowledgements are unavailable".into()))?;
                let rows = rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|_| DatastoreError::InternalError("Sync tombstone acknowledgements are invalid".into()))?;
                if rows.len() > 100_000 { return Err(DatastoreError::InternalError("Sync tombstone acknowledgements exceed the recovery limit".into())); }
                rows.into_iter().map(|(origin_device_id, local_event_id, tombstone_counter, device_id, acknowledged_at)| {
                    Ok(SyncRecoveryTombstoneAckV1 {
                        origin_device_id: origin_device_id.try_into()
                            .map_err(|_| DatastoreError::InternalError("Sync tombstone acknowledgement is invalid".into()))?,
                        local_event_id: u64::try_from(local_event_id).ok().filter(|value| *value > 0)
                            .ok_or_else(|| DatastoreError::InternalError("Sync tombstone acknowledgement is invalid".into()))?,
                        tombstone_counter: u64::try_from(tombstone_counter).ok().filter(|value| *value > 0)
                            .ok_or_else(|| DatastoreError::InternalError("Sync tombstone acknowledgement is invalid".into()))?,
                        device_id: device_id.try_into()
                            .map_err(|_| DatastoreError::InternalError("Sync tombstone acknowledgement is invalid".into()))?,
                        acknowledged_at,
                    })
                }).collect::<Result<Vec<_>, DatastoreError>>()?
            } else { Vec::new() };
            (trusted_devices, operations, stream_heads, tombstone_acknowledgements)
        } else {
            (Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
        let mut counter_by_device = counters.into_iter()
            .map(|counter| (counter.device_id, counter.last_counter))
            .collect::<BTreeMap<_, _>>();
        for operation in &operations {
            counter_by_device.entry(operation.device_id)
                .and_modify(|counter| *counter = (*counter).max(operation.counter))
                .or_insert(operation.counter);
        }
        let mut counters = counter_by_device.into_iter()
            .map(|(device_id, last_counter)| SyncRecoveryCounterV1 { device_id, last_counter })
            .collect::<Vec<_>>();
        counters.sort_by_key(|counter| counter.device_id);
        Ok(SyncRecoveryStateV1 {
            schema_version: aw_models::SYNC_SCHEMA_VERSION_V1,
            key_epoch,
            baseline_complete,
            bucket_mappings,
            event_mappings,
            trusted_devices,
            operations,
            stream_heads,
            counters,
            tombstone_acknowledgements,
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn prepare_sync_snapshot_mappings(&mut self, conn: &Connection) -> Result<(), DatastoreError> {
        let Some(identity) = self.get_sync_device_identity(conn)? else { return Ok(()); };
        let _material = self.get_sync_key_material(conn)?
            .ok_or_else(|| DatastoreError::InternalError("Sync keys are unavailable".into()))?;
        with_savepoint(conn, "sync_snapshot_mappings", || {
            let bucket_ids = self.buckets_cache.keys().cloned().collect::<Vec<_>>();
            for bucket_id in bucket_ids {
                let events = self.get_events_unclipped(conn, &bucket_id, None, None, None)?;
                if events.is_empty() { continue; }
                let (sync_bucket_id, _) = self.ensure_local_sync_bucket(conn, &bucket_id)?;
                for event in events {
                    let event_id = event.id
                        .ok_or_else(|| DatastoreError::InternalError("Sync snapshot event has no local ID".into()))?;
                    self.ensure_local_sync_event_mapping(
                        conn, identity.device_id(), &bucket_id, event_id, &sync_bucket_id,
                    )?;
                }
            }
            Ok(())
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn install_sync_recovery_data(
        &self,
        conn: &Connection,
        material: &crate::SyncKeyMaterial,
        snapshot: &crate::SyncSnapshotV1,
        state: &SyncRecoveryStateV1,
        identity: &SyncDeviceIdentity,
    ) -> Result<(), DatastoreError> {
        with_savepoint(conn, "sync_recovery_install", || {
            let existing = conn.query_row(
                "SELECT 1 FROM sync_key_material WHERE id = 1",
                [],
                |_| Ok(()),
            ).optional().map_err(|_| DatastoreError::InternalError("Sync key material is unavailable".into()))?;
            if existing.is_some() {
                return Err(DatastoreError::InternalError("Existing sync keys must be preserved".into()));
            }
            let existing_snapshot = conn.query_row(
                "SELECT 1 FROM sync_snapshot_current WHERE id = 1",
                [],
                |_| Ok(()),
            ).optional().map_err(|_| DatastoreError::InternalError("Stored sync snapshot is unavailable".into()))?;
            if existing_snapshot.is_some() {
                return Err(DatastoreError::InternalError("Existing sync snapshot must be preserved".into()));
            }
            if state.schema_version != aw_models::SYNC_SCHEMA_VERSION_V1
                || state.key_epoch != material.key_epoch()
                || (state.baseline_complete == false
                    && (!state.operations.is_empty() || !state.stream_heads.is_empty() || !state.tombstone_acknowledgements.is_empty()))
            {
                return Err(DatastoreError::InternalError("Sync recovery state does not match its key epoch".into()));
            }
            let mut trusted = BTreeSet::new();
            for peer in &state.trusted_devices {
                if peer.device_id == *identity.device_id()
                    || !trusted.insert(peer.device_id)
                    || DateTime::parse_from_rfc3339(&peer.paired_at).is_err()
                {
                    return Err(DatastoreError::InternalError("Sync recovery contains an invalid trusted device".into()));
                }
            }
            let mut bucket_ids = BTreeSet::new();
            let mut local_bucket_ids = BTreeSet::new();
            for mapping in &state.bucket_mappings {
                mapping.descriptor.validate()
                    .map_err(|_| DatastoreError::InternalError("Sync recovery contains an invalid bucket descriptor".into()))?;
                let bucket = self.get_bucket(&mapping.local_bucket_id).ok();
                let active_events = state.event_mappings.iter().any(|event| {
                    event.sync_bucket_id == mapping.sync_bucket_id && !event.deleted
                });
                if !bucket_ids.insert(mapping.sync_bucket_id)
                    || !local_bucket_ids.insert(mapping.local_bucket_id.as_str())
                    || bucket.as_ref().is_some_and(|bucket| {
                        bucket._type != mapping.descriptor.bucket_type
                            || bucket.client != mapping.descriptor.client
                            || bucket.data.iter().map(|(key, value)| (key.clone(), value.clone())).collect::<BTreeMap<_, _>>() != mapping.descriptor.data
                    })
                    || (bucket.is_none() && active_events)
                {
                    return Err(DatastoreError::InternalError("Sync recovery bucket mapping does not match its activity bucket".into()));
                }
                let descriptor_json = serde_json::to_string(&mapping.descriptor)
                    .map_err(|_| DatastoreError::InternalError("Sync recovery bucket mapping is invalid".into()))?;
                conn.execute(
                    "INSERT INTO sync_bucket_mappings(sync_bucket_id,local_bucket_id,descriptor_json) VALUES (?1,?2,?3)",
                    params![&mapping.sync_bucket_id[..], mapping.local_bucket_id, descriptor_json],
                ).map_err(|_| DatastoreError::InternalError("Sync recovery bucket mapping could not be stored".into()))?;
            }
            let mut event_ids = BTreeSet::new();
            for mapping in &state.event_mappings {
                if mapping.origin_event_id == 0 || mapping.origin_event_id > i64::MAX as u64
                    || mapping.local_event_id.is_some_and(|id| id == 0 || id > i64::MAX as u64)
                    || !event_ids.insert((mapping.origin_device_id, mapping.origin_event_id))
                    || !bucket_ids.contains(&mapping.sync_bucket_id)
                    || state.bucket_mappings.iter().find(|bucket| bucket.sync_bucket_id == mapping.sync_bucket_id)
                        .is_none_or(|bucket| bucket.local_bucket_id != mapping.local_bucket_id)
                    || (!mapping.deleted && mapping.local_event_id.is_none())
                {
                    return Err(DatastoreError::InternalError("Sync recovery contains an invalid event mapping".into()));
                }
                if let Some(local_event_id) = mapping.local_event_id {
                    if !mapping.deleted {
                        let exists = conn.query_row(
                            "SELECT 1 FROM events e JOIN buckets b ON b.id = e.bucketrow WHERE b.name = ?1 AND e.id = ?2",
                            params![mapping.local_bucket_id, local_event_id as i64],
                            |_| Ok(()),
                        ).optional().map_err(|_| DatastoreError::InternalError("Sync recovery event mapping is unavailable".into()))?.is_some();
                        if !exists { return Err(DatastoreError::InternalError("Sync recovery event mapping has no activity row".into())); }
                    }
                }
                conn.execute(
                    "INSERT INTO sync_event_mappings(origin_device_id,origin_event_id,sync_bucket_id,local_bucket_id,local_event_id,deleted) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![&mapping.origin_device_id[..], mapping.origin_event_id as i64, &mapping.sync_bucket_id[..], mapping.local_bucket_id, mapping.local_event_id.map(|id| id as i64), mapping.deleted],
                ).map_err(|_| DatastoreError::InternalError("Sync recovery event mapping could not be stored".into()))?;
            }
            let mut counters = BTreeMap::new();
            for counter in &state.counters {
                if counter.last_counter == 0 || counter.last_counter > i64::MAX as u64
                    || counters.insert(counter.device_id, counter.last_counter).is_some()
                {
                    return Err(DatastoreError::InternalError("Sync recovery contains an invalid operation counter".into()));
                }
            }
            let mut known_tombstones = BTreeSet::new();
            for stored in &state.operations {
                if stored.key_epoch != material.key_epoch() || stored.counter == 0 || stored.counter > i64::MAX as u64
                    || !trusted.contains(&stored.device_id)
                    || counters.get(&stored.device_id).is_none_or(|counter| *counter < stored.counter)
                    || digest(&SHA256, stored.operation_json.as_bytes()).as_ref() != &stored.content_hash[..]
                {
                    return Err(DatastoreError::InternalError("Sync recovery contains an invalid stored operation".into()));
                }
                let operation: SyncOperationV1 = serde_json::from_str(&stored.operation_json)
                    .map_err(|_| DatastoreError::InternalError("Sync recovery contains an invalid stored operation".into()))?;
                operation.validate()
                    .map_err(|_| DatastoreError::InternalError("Sync recovery contains an invalid stored operation".into()))?;
                if operation.device_id != base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(stored.device_id)
                    || operation.counter != stored.counter
                {
                    return Err(DatastoreError::InternalError("Sync recovery operation identity does not match its record".into()));
                }
                if operation.kind == SyncOperationKindV1::Tombstone {
                    let origin: [u8; 16] = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&operation.origin_device_id)
                        .map_err(|_| DatastoreError::InternalError("Sync recovery tombstone identity is invalid".into()))?
                        .try_into().map_err(|_| DatastoreError::InternalError("Sync recovery tombstone identity is invalid".into()))?;
                    let event_id = operation.local_event_id
                        .ok_or_else(|| DatastoreError::InternalError("Sync recovery tombstone identity is invalid".into()))?;
                    known_tombstones.insert((origin, event_id, operation.counter));
                }
                self.put_sync_operation(conn, stored)?;
            }
            for (device_id, last_counter) in counters {
                conn.execute(
                    "INSERT INTO sync_device_counters(device_id,last_counter) VALUES (?1,?2)",
                    params![&device_id[..], last_counter as i64],
                ).map_err(|_| DatastoreError::InternalError("Sync recovery operation counter could not be stored".into()))?;
            }
            let mut stream_devices = BTreeSet::new();
            for head in &state.stream_heads {
                if head.revision == 0 || head.revision > i64::MAX as u64
                    || !trusted.contains(&head.device_id)
                    || !stream_devices.insert(head.device_id)
                {
                    return Err(DatastoreError::InternalError("Sync recovery contains an invalid stream checkpoint".into()));
                }
                conn.execute(
                    "INSERT INTO sync_stream_heads(vault_id,key_epoch,device_id,revision,head_hash) VALUES (?1,?2,?3,?4,?5)",
                    params![&material.vault_id()[..], material.key_epoch() as i64, &head.device_id[..], head.revision as i64, &head.head_hash[..]],
                ).map_err(|_| DatastoreError::InternalError("Sync recovery stream checkpoint could not be stored".into()))?;
            }
            for acknowledgement in &state.tombstone_acknowledgements {
                if !trusted.contains(&acknowledgement.device_id)
                    || !known_tombstones.contains(&(acknowledgement.origin_device_id, acknowledgement.local_event_id, acknowledgement.tombstone_counter))
                    || DateTime::parse_from_rfc3339(&acknowledgement.acknowledged_at).is_err()
                {
                    return Err(DatastoreError::InternalError("Sync recovery contains an invalid tombstone acknowledgement".into()));
                }
                conn.execute(
                    "INSERT INTO sync_tombstone_acknowledgements(origin_device_id,local_event_id,tombstone_counter,device_id,acknowledged_at) VALUES (?1,?2,?3,?4,?5)",
                    params![&acknowledgement.origin_device_id[..], acknowledgement.local_event_id as i64,
                        acknowledgement.tombstone_counter as i64, &acknowledgement.device_id[..], acknowledgement.acknowledged_at],
                ).map_err(|_| DatastoreError::InternalError("Sync recovery tombstone acknowledgement could not be stored".into()))?;
            }
            self.create_sync_device_identity(conn, identity)?;
            if state.baseline_complete {
                let acknowledged_at = Utc::now().to_rfc3339();
                for (origin, event_id, counter) in &known_tombstones {
                    conn.execute(
                        "INSERT OR IGNORE INTO sync_tombstone_acknowledgements(origin_device_id,local_event_id,tombstone_counter,device_id,acknowledged_at) VALUES (?1,?2,?3,?4,?5)",
                        params![&origin[..], *event_id as i64, *counter as i64, &identity.device_id()[..], acknowledged_at],
                    ).map_err(|_| DatastoreError::InternalError("Restored device tombstone acknowledgement could not be stored".into()))?;
                }
            }
            for peer in &state.trusted_devices {
                conn.execute(
                    "INSERT INTO sync_trusted_devices(device_id,x25519_public_key,ed25519_public_key,paired_at,revoked_at,key_epoch) VALUES (?1,?2,?3,?4,NULL,?5)",
                    params![&peer.device_id[..], &peer.x25519_public_key[..], &peer.ed25519_public_key[..], peer.paired_at, material.key_epoch() as i64],
                ).map_err(|_| DatastoreError::InternalError("Sync recovery trusted device could not be stored".into()))?;
            }
            self.insert_sync_key_material(conn, material)?;
            self.replace_sync_snapshot(conn, snapshot, material)?;
            if state.baseline_complete {
                let watermark: i64 = conn.query_row("SELECT COALESCE(MAX(id),0) FROM events", [], |row| row.get(0))
                    .map_err(|_| DatastoreError::InternalError("Sync recovery baseline watermark is unavailable".into()))?;
                conn.execute(
                    "INSERT INTO sync_journal_state(id,active,key_epoch,baseline_max_event_id,baseline_cursor,baseline_complete) VALUES (1,1,?1,?2,?2,1)",
                    params![material.key_epoch() as i64, watermark],
                ).map_err(|_| DatastoreError::InternalError("Sync recovery baseline state could not be stored".into()))?;
            }
            conn.execute("UPDATE sync_runtime_control SET enabled = 0 WHERE id = 1", [])
                .map_err(|_| DatastoreError::InternalError("Could not disable sync during recovery".into()))?;
            Ok(())
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn install_sync_recovery(
        &self,
        conn: &Connection,
        material: &crate::SyncKeyMaterial,
        snapshot: &crate::SyncSnapshotV1,
    ) -> Result<(), DatastoreError> {
        with_savepoint(conn, "sync_recovery_install", || {
            let existing = conn.query_row("SELECT 1 FROM sync_key_material WHERE id = 1", [], |_| Ok(()))
                .optional().map_err(|_| DatastoreError::InternalError("Sync key material is unavailable".into()))?;
            let existing_snapshot = conn.query_row("SELECT 1 FROM sync_snapshot_current WHERE id = 1", [], |_| Ok(()))
                .optional().map_err(|_| DatastoreError::InternalError("Stored sync snapshot is unavailable".into()))?;
            if existing.is_some() || existing_snapshot.is_some() {
                return Err(DatastoreError::InternalError("Existing sync recovery data must be preserved".into()));
            }
            self.insert_sync_key_material(conn, material)?;
            self.replace_sync_snapshot(conn, snapshot, material)?;
            conn.execute("UPDATE sync_runtime_control SET enabled = 0 WHERE id = 1", [])
                .map_err(|_| DatastoreError::InternalError("Could not disable sync during recovery".into()))?;
            Ok(())
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_object(
        &self,
        conn: &Connection,
        object_id: &str,
    ) -> Result<Option<aw_models::SyncEnvelopeV1>, DatastoreError> {
        validate_sync_id(object_id)?;
        let stored = conn.query_row(
            "SELECT vault_id, key_epoch, nonce, ciphertext FROM sync_objects WHERE object_id = ?1",
            [object_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Stored sync object is unavailable".into()))?;
        stored.map(|(vault_id, key_epoch, nonce, ciphertext)| {
            let envelope = aw_models::SyncEnvelopeV1 {
                schema_version: 1,
                object_id: object_id.to_owned(),
                vault_id,
                key_epoch: u64::try_from(key_epoch)
                    .map_err(|_| DatastoreError::InternalError("Stored sync object is invalid".into()))?,
                nonce,
                ciphertext,
            };
            envelope.validate().map_err(|_| DatastoreError::InternalError("Stored sync object is invalid".into()))?;
            Ok(envelope)
        }).transpose()
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn put_sync_object(
        &self,
        conn: &Connection,
        envelope: &aw_models::SyncEnvelopeV1,
        stored_at: &str,
    ) -> Result<bool, DatastoreError> {
        envelope.validate().map_err(|_| DatastoreError::InternalError("Invalid encrypted sync object".into()))?;
        DateTime::parse_from_rfc3339(stored_at)
            .map_err(|_| DatastoreError::InternalError("Invalid sync object time".into()))?;
        if let Some(existing) = self.get_sync_object(conn, &envelope.object_id)? {
            return if existing == *envelope { Ok(false) }
                else { Err(DatastoreError::InternalError("Sync object ID already contains different ciphertext".into())) };
        }
        with_savepoint(conn, "sync_object_put", || {
            conn.execute(
                "INSERT INTO sync_objects(object_id, vault_id, key_epoch, nonce, ciphertext, stored_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![&envelope.object_id, &envelope.vault_id, i64::try_from(envelope.key_epoch).map_err(|_| DatastoreError::InternalError("Invalid sync object epoch".into()))?, &envelope.nonce, &envelope.ciphertext, stored_at],
            ).map_err(|_| DatastoreError::InternalError("Sync object ID already contains different ciphertext".into()))?;
            conn.execute(
                "INSERT INTO sync_object_history(object_id, action, occurred_at) VALUES (?1, 'stored', ?2)",
                params![&envelope.object_id, stored_at],
            ).map_err(|_| DatastoreError::InternalError("Could not record sync object metadata".into()))?;
            Ok(true)
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_objects(
        &self,
        conn: &Connection,
        vault_id: &str,
        after_object_id: Option<&str>,
        limit: usize,
    ) -> Result<crate::SyncObjectPageV1, DatastoreError> {
        validate_sync_id(vault_id)?;
        if let Some(after) = after_object_id { validate_sync_id(after)?; }
        let limit = limit.clamp(1, 64);
        let mut statement = conn.prepare_cached(
            "SELECT object_id FROM sync_objects WHERE vault_id = ?1 AND (?2 IS NULL OR object_id > ?2) ORDER BY object_id LIMIT ?3",
        ).map_err(|_| DatastoreError::InternalError("Could not query encrypted sync objects".into()))?;
        let rows = statement.query_map(params![vault_id, after_object_id, (limit + 1) as i64], |row| row.get::<_, String>(0))
            .map_err(|_| DatastoreError::InternalError("Could not query encrypted sync objects".into()))?;
        let mut ids = rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| DatastoreError::InternalError("Stored sync object metadata is invalid".into()))?;
        let next_cursor = if ids.len() > limit {
            ids.truncate(limit);
            ids.last().cloned()
        } else { None };
        let objects = ids.iter().map(|object_id| self.get_sync_object(conn, object_id)?.ok_or_else(|| {
            DatastoreError::InternalError("Stored sync object disappeared during listing".into())
        })).collect::<Result<Vec<_>, _>>()?;
        Ok(crate::SyncObjectPageV1 { objects, next_cursor })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn delete_sync_object_after_tombstones(
        &self,
        conn: &Connection,
        object_id: &str,
        tombstones: &[crate::SyncTombstoneIdentityV1],
        deleted_at: &str,
    ) -> Result<bool, DatastoreError> {
        validate_sync_id(object_id)?;
        if tombstones.is_empty() || tombstones.len() > 10_000 {
            return Err(DatastoreError::InternalError("Sync object deletion needs bounded tombstone proof".into()));
        }
        DateTime::parse_from_rfc3339(deleted_at)
            .map_err(|_| DatastoreError::InternalError("Invalid sync object time".into()))?;
        with_savepoint(conn, "sync_object_delete", || {
            if self.get_sync_object(conn, object_id)?.is_none() { return Ok(false); }
            for tombstone in tombstones {
                if !self.can_collect_sync_tombstone(
                    conn,
                    &tombstone.origin_device_id,
                    tombstone.local_event_id,
                    tombstone.tombstone_counter,
                )? {
                    return Err(DatastoreError::InternalError("Sync tombstone is still awaiting an active device acknowledgement".into()));
                }
            }
            conn.execute("DELETE FROM sync_objects WHERE object_id = ?1", [object_id])
                .map_err(|_| DatastoreError::InternalError("Could not delete sync object".into()))?;
            conn.execute(
                "INSERT INTO sync_object_history(object_id, action, occurred_at) VALUES (?1, 'deleted', ?2)",
                params![object_id, deleted_at],
            ).map_err(|_| DatastoreError::InternalError("Could not record sync object metadata".into()))?;
            Ok(true)
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_object_history(
        &self,
        conn: &Connection,
        limit: usize,
    ) -> Result<Vec<crate::SyncObjectHistoryV1>, DatastoreError> {
        let mut statement = conn.prepare_cached(
            "SELECT object_id, action, occurred_at FROM sync_object_history ORDER BY id DESC LIMIT ?1",
        ).map_err(|_| DatastoreError::InternalError("Could not query sync object history".into()))?;
        let rows = statement.query_map([limit.clamp(1, 1000) as i64], |row| {
            Ok(crate::SyncObjectHistoryV1 {
                object_id: row.get(0)?,
                action: row.get(1)?,
                occurred_at: row.get(2)?,
            })
        }).map_err(|_| DatastoreError::InternalError("Could not query sync object history".into()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| DatastoreError::InternalError("Stored sync object history is invalid".into()))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_enabled(&self, conn: &Connection) -> Result<bool, DatastoreError> {
        conn.query_row("SELECT enabled FROM sync_runtime_control WHERE id = 1", [], |row| {
            row.get::<_, bool>(0)
        }).optional().map(|enabled| enabled.unwrap_or(false))
            .map_err(|_| DatastoreError::InternalError("Sync state is unavailable".into()))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_egress_consent(
        &self,
        conn: &Connection,
    ) -> Result<Option<crate::SyncEgressConsentV1>, DatastoreError> {
        let stored = conn.query_row(
            "SELECT enabled, destination_id, purpose_id FROM sync_runtime_control WHERE id = 1",
            [],
            |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, Option<String>>(2)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Sync consent is unavailable".into()))?;
        match stored {
            Some((true, Some(destination_id), Some(purpose_id))) => {
                Ok(Some(crate::SyncEgressConsentV1 { destination_id, purpose_id }))
            }
            Some((true, _, _)) => Err(DatastoreError::InternalError("Stored sync consent is invalid".into())),
            _ => Ok(None),
        }
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn set_sync_enabled(
        &self,
        conn: &Connection,
        enabled: bool,
        destination_id: Option<&str>,
        purpose_id: Option<&str>,
    ) -> Result<(), DatastoreError> {
        with_savepoint(conn, "sync_runtime_control", || {
            if enabled {
                if !destination_id.is_some_and(valid_egress_identifier)
                    || !purpose_id.is_some_and(valid_egress_identifier)
                {
                    return Err(DatastoreError::InternalError("Sync consent requires signed destination and purpose IDs".into()));
                }
                let configured = conn.query_row(
                    "SELECT 1 FROM sync_key_material k JOIN sync_recovery_confirmation r ON r.id = 1 JOIN sync_snapshot_current s ON s.id = 1 JOIN sync_trusted_devices d ON d.revoked_at IS NULL AND d.key_epoch = k.key_epoch AND d.ed25519_public_key IS NOT NULL WHERE k.id = 1 LIMIT 1",
                    [],
                    |_| Ok(()),
                ).optional().map_err(|_| DatastoreError::InternalError("Sync prerequisites are unavailable".into()))?.is_some();
                if !configured || self.egress_kill_switch(conn)? {
                    return Err(DatastoreError::InternalError("Sync requires paired current-epoch devices, a saved recovery kit, a current encrypted snapshot, and the privacy kill switch off".into()));
                }
            }
            conn.execute(
                "INSERT INTO sync_runtime_control(id, enabled, destination_id, purpose_id) VALUES (1, ?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, destination_id = excluded.destination_id, purpose_id = excluded.purpose_id",
                params![enabled, if enabled { destination_id } else { None }, if enabled { purpose_id } else { None }],
            ).map_err(|_| DatastoreError::InternalError("Could not update sync state".into()))?;
            Ok(())
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub(super) fn replace_sync_snapshot(
        &self,
        conn: &Connection,
        snapshot: &crate::SyncSnapshotV1,
        material: &crate::SyncKeyMaterial,
    ) -> Result<(), DatastoreError> {
        let vault_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(material.vault_id());
        let mut object_ids = BTreeSet::new();
        if snapshot.envelopes.is_empty() || snapshot.envelopes.len() > i64::MAX as usize {
            return Err(DatastoreError::InternalError("Sync snapshot is empty or too large".into()));
        }
        for envelope in &snapshot.envelopes {
            envelope.validate().map_err(|_| DatastoreError::InternalError("Invalid encrypted sync snapshot".into()))?;
            if envelope.vault_id != vault_id
                || envelope.key_epoch != material.key_epoch()
                || !object_ids.insert(envelope.object_id.as_str())
            {
                return Err(DatastoreError::InternalError("Sync snapshot does not match the current key epoch".into()));
            }
        }
        conn.execute("DELETE FROM sync_snapshot_chunks", [])
            .map_err(|_| DatastoreError::InternalError("Could not replace sync snapshot".into()))?;
        conn.execute("DELETE FROM sync_snapshot_current WHERE id = 1", [])
            .map_err(|_| DatastoreError::InternalError("Could not replace sync snapshot".into()))?;
        for (index, envelope) in snapshot.envelopes.iter().enumerate() {
            let key_epoch = i64::try_from(envelope.key_epoch)
                .map_err(|_| DatastoreError::InternalError("Invalid sync snapshot epoch".into()))?;
            conn.execute(
                "INSERT INTO sync_snapshot_chunks(snapshot_id, chunk_index, object_id, vault_id, key_epoch, nonce, ciphertext) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![&snapshot.snapshot_id[..], index as i64, envelope.object_id, envelope.vault_id, key_epoch, envelope.nonce, envelope.ciphertext],
            ).map_err(|_| DatastoreError::InternalError("Could not store encrypted sync snapshot".into()))?;
        }
        conn.execute(
            "INSERT INTO sync_snapshot_current(id, snapshot_id) VALUES (1, ?1)",
            [&snapshot.snapshot_id[..]],
        ).map_err(|_| DatastoreError::InternalError("Could not select current sync snapshot".into()))?;
        Ok(())
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn insert_sync_key_material(
        &self,
        conn: &Connection,
        material: &crate::SyncKeyMaterial,
    ) -> Result<(), DatastoreError> {
        let key_epoch = i64::try_from(material.key_epoch())
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync key material".into()))?;
        conn.execute(
            "INSERT INTO sync_key_material(id, account_root_key, vault_id, key_epoch, wrapped_nonce, wrapped_ciphertext) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                &material.account_root_key()[..],
                &material.vault_id()[..],
                key_epoch,
                &material.wrapped_nonce()[..],
                &material.wrapped_ciphertext()[..],
            ],
        )
        .map_err(|_| DatastoreError::InternalError("Sync key material already exists or cannot be stored".into()))?;
        Ok(())
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn update_sync_key_material(
        &self,
        conn: &Connection,
        material: &crate::SyncKeyMaterial,
    ) -> Result<(), DatastoreError> {
        let next_epoch = i64::try_from(material.key_epoch())
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync key material".into()))?;
        let current = conn.query_row(
            "SELECT account_root_key, vault_id, key_epoch, wrapped_nonce, wrapped_ciphertext FROM sync_key_material WHERE id = 1",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Stored sync keys are unavailable".into()))?;
        if let Some((root, vault_id, epoch, nonce, ciphertext)) = current {
            if vault_id.as_slice() != material.vault_id() || next_epoch < epoch {
                return Err(DatastoreError::InternalError("Sync key replacement is stale or belongs to another vault".into()));
            }
            if next_epoch == epoch {
                let same = root.as_slice() == material.account_root_key()
                    && nonce.as_slice() == material.wrapped_nonce()
                    && ciphertext.as_slice() == material.wrapped_ciphertext();
                if same { return Ok(()); }
                return Err(DatastoreError::InternalError("Sync keys cannot change without advancing the epoch".into()));
            }
            conn.execute(
                "UPDATE sync_key_material SET account_root_key = ?1, vault_id = ?2, key_epoch = ?3, wrapped_nonce = ?4, wrapped_ciphertext = ?5 WHERE id = 1",
                params![&material.account_root_key()[..], &material.vault_id()[..], next_epoch, &material.wrapped_nonce()[..], &material.wrapped_ciphertext()[..]],
            ).map_err(|_| DatastoreError::InternalError("Could not replace sync keys".into()))?;
            conn.execute("DELETE FROM sync_recovery_confirmation WHERE id = 1", [])
                .map_err(|_| DatastoreError::InternalError("Could not invalidate sync recovery confirmation".into()))?;
            conn.execute("DELETE FROM sync_snapshot_chunks", [])
                .map_err(|_| DatastoreError::InternalError("Could not remove the stale sync snapshot".into()))?;
            conn.execute("DELETE FROM sync_snapshot_current WHERE id = 1", [])
                .map_err(|_| DatastoreError::InternalError("Could not remove the stale sync snapshot".into()))?;
            conn.execute("UPDATE sync_runtime_control SET enabled = 0 WHERE id = 1", [])
                .map_err(|_| DatastoreError::InternalError("Could not disable sync after key rotation".into()))?;
        } else {
            self.insert_sync_key_material(conn, material)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn rotate_sync_key_material(
        &self,
        conn: &Connection,
        material: &crate::SyncKeyMaterial,
        snapshot: &crate::SyncSnapshotV1,
        revoke_device: Option<&[u8; 16]>,
        occurred_at: &str,
    ) -> Result<bool, DatastoreError> {
        DateTime::parse_from_rfc3339(occurred_at)
            .map_err(|_| DatastoreError::InternalError("Invalid sync device time".into()))?;
        with_savepoint(conn, "sync_key_rotation", || {
            let current_epoch: i64 = conn.query_row(
                "SELECT key_epoch FROM sync_key_material WHERE id = 1",
                [],
                |row| row.get(0),
            ).optional().map_err(|_| DatastoreError::InternalError("Sync key material is unavailable".into()))?
                .ok_or_else(|| DatastoreError::InternalError("Create sync keys before rotating them".into()))?;
            if i64::try_from(material.key_epoch()).ok().filter(|epoch| *epoch > current_epoch).is_none() {
                return Err(DatastoreError::InternalError("Sync key rotation must advance the epoch".into()));
            }
            if let Some(device_id) = revoke_device {
                let active = conn.query_row(
                    "SELECT 1 FROM sync_trusted_devices WHERE device_id = ?1 AND revoked_at IS NULL",
                    [&device_id[..]],
                    |_| Ok(()),
                ).optional().map_err(|_| DatastoreError::InternalError("Could not inspect sync device access".into()))?.is_some();
                if !active { return Ok(false); }
            }
            self.update_sync_key_material(conn, material)?;
            self.replace_sync_snapshot(conn, snapshot, material)?;
            conn.execute("UPDATE sync_runtime_control SET enabled = 0,destination_id = NULL,purpose_id = NULL WHERE id = 1", [])
                .map_err(|_| DatastoreError::InternalError("Sync consent could not be paused for key rotation".into()))?;
            conn.execute("DELETE FROM sync_tombstone_acknowledgements", [])
                .map_err(|_| DatastoreError::InternalError("Could not reset old tombstone acknowledgements".into()))?;
            if let Some(device_id) = revoke_device {
                conn.execute(
                    "UPDATE sync_trusted_devices SET revoked_at = ?2 WHERE device_id = ?1 AND revoked_at IS NULL",
                    params![&device_id[..], occurred_at],
                ).map_err(|_| DatastoreError::InternalError("Could not revoke sync device".into()))?;
                conn.execute(
                    "INSERT INTO sync_device_access_history(device_id, action, occurred_at) VALUES (?1, 'revoked', ?2)",
                    params![&device_id[..], occurred_at],
                ).map_err(|_| DatastoreError::InternalError("Could not store sync device history".into()))?;
            }
            Ok(true)
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_recovery_confirmation(
        &self,
        conn: &Connection,
    ) -> Result<Option<String>, DatastoreError> {
        conn.query_row(
            "SELECT confirmed_at FROM sync_recovery_confirmation WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| DatastoreError::InternalError("Recovery confirmation is unavailable".into()))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn confirm_sync_recovery_saved(
        &self,
        conn: &Connection,
        confirmed_at: &str,
    ) -> Result<(), DatastoreError> {
        DateTime::parse_from_rfc3339(confirmed_at)
            .map_err(|_| DatastoreError::InternalError("Invalid recovery confirmation".into()))?;
        with_savepoint(conn, "sync_recovery_confirmation", || {
            let has_keys = conn
                .query_row("SELECT 1 FROM sync_key_material WHERE id = 1", [], |_| Ok(()))
                .optional()
                .map_err(|_| DatastoreError::InternalError("Sync key material is unavailable".into()))?
                .is_some();
            if !has_keys {
                return Err(DatastoreError::InternalError("Create or restore sync keys before confirming recovery".into()));
            }
            conn.execute(
                "INSERT INTO sync_recovery_confirmation(id, confirmed_at) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET confirmed_at = excluded.confirmed_at",
                [confirmed_at],
            )
            .map_err(|_| DatastoreError::InternalError("Could not store recovery confirmation".into()))?;
            Ok(())
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn record_sync_pairing(
        &self,
        conn: &Connection,
        material: Option<&crate::SyncKeyMaterial>,
        offer_id: &[u8; 16],
        device_id: &[u8; 16],
        x25519_public_key: &[u8; 32],
        ed25519_public_key: &[u8; 32],
        occurred_at: &str,
    ) -> Result<(), DatastoreError> {
        DateTime::parse_from_rfc3339(occurred_at)
            .map_err(|_| DatastoreError::InternalError("Invalid sync pairing time".into()))?;
        with_savepoint(conn, "sync_pairing_commit", || {
            conn.execute(
                "INSERT INTO sync_pairing_offers(offer_id, peer_device_id, completed_at) VALUES (?1, ?2, ?3)",
                params![&offer_id[..], &device_id[..], occurred_at],
            )
            .map_err(|_| DatastoreError::InternalError("This pairing offer was already consumed".into()))?;
            if let Some(material) = material {
                self.update_sync_key_material(conn, material)?;
            }
            let key_epoch: i64 = conn.query_row(
                "SELECT key_epoch FROM sync_key_material WHERE id = 1",
                [],
                |row| row.get(0),
            ).map_err(|_| DatastoreError::InternalError("Sync key material is unavailable".into()))?;
            let was_revoked = conn
                .query_row(
                    "SELECT revoked_at IS NOT NULL FROM sync_trusted_devices WHERE device_id = ?1",
                    [&device_id[..]],
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map_err(|_| DatastoreError::InternalError("Could not inspect sync device history".into()))?
                .unwrap_or(false);
            if was_revoked {
                return Err(DatastoreError::InternalError("A revoked device cannot be paired again".into()));
            }
            conn.execute(
                "INSERT INTO sync_trusted_devices(device_id, x25519_public_key, ed25519_public_key, paired_at, revoked_at, key_epoch) VALUES (?1, ?2, ?3, ?4, NULL, ?5) ON CONFLICT(device_id) DO UPDATE SET x25519_public_key = excluded.x25519_public_key, ed25519_public_key = excluded.ed25519_public_key, paired_at = excluded.paired_at, revoked_at = NULL, key_epoch = excluded.key_epoch",
                params![&device_id[..], &x25519_public_key[..], &ed25519_public_key[..], occurred_at, key_epoch],
            )
            .map_err(|_| DatastoreError::InternalError("Could not store trusted sync device".into()))?;
            conn.execute(
                "INSERT INTO sync_device_access_history(device_id, action, occurred_at) VALUES (?1, 'paired', ?2)",
                params![&device_id[..], occurred_at],
            )
            .map_err(|_| DatastoreError::InternalError("Could not store sync device history".into()))?;
            Ok(())
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn create_sync_device_identity(
        &self,
        conn: &Connection,
        identity: &SyncDeviceIdentity,
    ) -> Result<(), DatastoreError> {
        conn.execute(
            "INSERT INTO sync_device_identity(id, device_id, private_key, signing_seed) VALUES (1, ?1, ?2, ?3)",
            params![&identity.device_id()[..], &identity.private_key()[..], &identity.signing_seed()[..]],
        )
        .map_err(|_| DatastoreError::InternalError("Sync device identity already exists or cannot be stored".into()))?;
        Ok(())
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_trusted_devices(
        &self,
        conn: &Connection,
    ) -> Result<Vec<SyncTrustedDevice>, DatastoreError> {
        let mut statement = conn
            .prepare_cached("SELECT device_id, x25519_public_key, ed25519_public_key, paired_at, revoked_at, key_epoch FROM sync_trusted_devices ORDER BY paired_at, device_id")
            .map_err(|_| DatastoreError::InternalError("Could not query trusted sync devices".into()))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|_| DatastoreError::InternalError("Could not query trusted sync devices".into()))?;
        rows.map(|row| {
            let (device_id, public_key, signing_public_key, paired_at, revoked_at, key_epoch) = row
                .map_err(|_| DatastoreError::InternalError("Stored sync device is invalid".into()))?;
            Ok(SyncTrustedDevice {
                device_id: device_id
                    .try_into()
                    .map_err(|_| DatastoreError::InternalError("Stored sync device is invalid".into()))?,
                x25519_public_key: public_key
                    .try_into()
                    .map_err(|_| DatastoreError::InternalError("Stored sync device is invalid".into()))?,
                ed25519_public_key: signing_public_key
                    .map(|key| key.try_into()
                        .map_err(|_| DatastoreError::InternalError("Stored sync device is invalid".into())))
                    .transpose()?,
                paired_at,
                revoked_at,
                key_epoch: u64::try_from(key_epoch)
                    .ok()
                    .filter(|epoch| *epoch > 0)
                    .ok_or_else(|| DatastoreError::InternalError("Stored sync device is invalid".into()))?,
            })
        })
        .collect()
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_device_access_history(
        &self,
        conn: &Connection,
        limit: usize,
    ) -> Result<Vec<SyncDeviceAccessEvent>, DatastoreError> {
        let mut statement = conn
            .prepare_cached("SELECT device_id, action, occurred_at FROM sync_device_access_history ORDER BY id DESC LIMIT ?1")
            .map_err(|_| DatastoreError::InternalError("Could not query sync device history".into()))?;
        let rows = statement
            .query_map([limit.min(1000) as i64], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })
            .map_err(|_| DatastoreError::InternalError("Could not query sync device history".into()))?;
        rows.map(|row| {
            let (device_id, action, occurred_at) = row
                .map_err(|_| DatastoreError::InternalError("Stored sync device history is invalid".into()))?;
            Ok(SyncDeviceAccessEvent {
                device_id: device_id
                    .try_into()
                    .map_err(|_| DatastoreError::InternalError("Stored sync device history is invalid".into()))?,
                action,
                occurred_at,
            })
        })
        .collect()
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn get_sync_manifest_head(
        &self,
        conn: &Connection,
        vault_id: &[u8; 16],
        key_epoch: u64,
        device_id: &[u8; 16],
    ) -> Result<Option<SyncManifestHeadV1>, DatastoreError> {
        let key_epoch_db = i64::try_from(key_epoch)
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync head epoch".into()))?;
        let stored = conn
            .query_row(
                "SELECT revision, head_hash FROM sync_stream_heads WHERE vault_id = ?1 AND key_epoch = ?2 AND device_id = ?3",
                params![&vault_id[..], key_epoch_db, &device_id[..]],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| DatastoreError::InternalError("Stored sync manifest head is unavailable".into()))?;
        let Some((revision, hash)) = stored else { return Ok(None); };
        let revision = u64::try_from(revision)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| DatastoreError::InternalError("Stored sync manifest head is invalid".into()))?;
        let head_hash = hash
            .try_into()
            .map_err(|_| DatastoreError::InternalError("Stored sync manifest head is invalid".into()))?;
        Ok(Some(SyncManifestHeadV1::new(revision, head_hash)))
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn commit_sync_manifest_head(
        &self,
        conn: &Connection,
        vault_id: &[u8; 16],
        key_epoch: u64,
        device_id: &[u8; 16],
        expected: SyncManifestHeadV1,
        next: SyncManifestHeadV1,
    ) -> Result<SyncHeadCommitV1, DatastoreError> {
        if expected.revision == 0 && expected.head_hash != [0; 32] {
            return Err(DatastoreError::InternalError("Invalid initial sync head".into()));
        }
        let next_revision = i64::try_from(next.revision)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync revision".into()))?;
        let key_epoch_db = i64::try_from(key_epoch)
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync head epoch".into()))?;
        with_savepoint(conn, "sync_manifest_head", || {
            let current = self.get_sync_manifest_head(conn, vault_id, key_epoch, device_id)?.unwrap_or_else(SyncManifestHeadV1::genesis);
            if next.revision == current.revision {
                return if next.head_hash == current.head_hash {
                    Ok(SyncHeadCommitV1::Duplicate)
                } else {
                    Err(DatastoreError::InternalError("Sync revision fork detected".into()))
                };
            }
            if next.revision < current.revision {
                return Err(DatastoreError::InternalError("Sync rollback rejected".into()));
            }
            if next.revision != current.revision.saturating_add(1) {
                return Err(DatastoreError::InternalError("Sync revision gap rejected".into()));
            }
            if expected != current {
                return Err(DatastoreError::InternalError("Sync manifest parent does not match stored head".into()));
            }
            conn.execute(
                "INSERT INTO sync_stream_heads(vault_id, key_epoch, device_id, revision, head_hash) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(vault_id,key_epoch,device_id) DO UPDATE SET revision = excluded.revision, head_hash = excluded.head_hash",
                params![&vault_id[..], key_epoch_db, &device_id[..], next_revision, &next.head_hash[..]],
            )
            .map_err(|_| DatastoreError::InternalError("Could not store sync manifest head".into()))?;
            Ok(SyncHeadCommitV1::Advanced)
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn next_sync_operation_counter(
        &self,
        conn: &Connection,
        device_id: &[u8; 16],
    ) -> Result<u64, DatastoreError> {
        with_savepoint(conn, "sync_device_counter", || {
            // ponytail: paired-device rows are small; add a shared indexed watermark only if device counts grow.
            let max_observed: i64 = conn.query_row(
                "SELECT COALESCE(MAX(value),0) FROM (SELECT MAX(last_counter) AS value FROM sync_device_counters UNION ALL SELECT MAX(counter) AS value FROM sync_operations)",
                [],
                |row| row.get(0),
            ).map_err(|_| DatastoreError::InternalError("Could not read sync operation counter".into()))?;
            let next = max_observed.checked_add(1)
                .ok_or_else(|| DatastoreError::InternalError("Sync operation counter exhausted".into()))?;
            conn.execute(
                "INSERT INTO sync_device_counters(device_id, last_counter) VALUES (?1, ?2) ON CONFLICT(device_id) DO UPDATE SET last_counter = excluded.last_counter",
                params![&device_id[..], next],
            )
            .map_err(|_| DatastoreError::InternalError("Could not store sync operation counter".into()))?;
            u64::try_from(next)
                .map_err(|_| DatastoreError::InternalError("Stored sync operation counter is invalid".into()))
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn put_sync_operation(
        &self,
        conn: &Connection,
        operation: &SyncStoredOperationV1,
    ) -> Result<bool, DatastoreError> {
        let counter = i64::try_from(operation.counter)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync operation counter".into()))?;
        let key_epoch = i64::try_from(operation.key_epoch)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync operation epoch".into()))?;
        if operation.operation_json.len() > SYNC_MAX_CHUNK_BYTES
            || serde_json::from_str::<Value>(&operation.operation_json)
                .map(|value| !value.is_object())
                .unwrap_or(true)
        {
            return Err(DatastoreError::InternalError("Invalid sync operation payload".into()));
        }
        let content_hash = digest(&SHA256, operation.operation_json.as_bytes());
        if content_hash.as_ref() != &operation.content_hash[..] {
            return Err(DatastoreError::InternalError("Sync operation content hash is invalid".into()));
        }
        with_savepoint(conn, "sync_operation_put", || {
            let stored = conn.query_row(
                "SELECT key_epoch, operation_json, content_hash FROM sync_operations WHERE device_id = ?1 AND counter = ?2",
                params![&operation.device_id[..], counter],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)),
            ).optional().map_err(|_| DatastoreError::InternalError("Could not inspect stored sync operation".into()))?;
            if let Some((stored_epoch, stored_json, stored_hash)) = stored {
                if stored_epoch == key_epoch
                    && stored_json == operation.operation_json
                    && stored_hash.as_slice() == &operation.content_hash[..]
                {
                    return Ok(false);
                }
                return Err(DatastoreError::InternalError("Sync operation counter was reused with different content".into()));
            }
            conn.execute(
                "INSERT INTO sync_operations(device_id,counter,key_epoch,operation_json,content_hash) VALUES (?1,?2,?3,?4,?5)",
                params![&operation.device_id[..], counter, key_epoch, &operation.operation_json, &operation.content_hash[..]],
            ).map_err(|_| DatastoreError::InternalError("Could not store sync operation".into()))?;
            Ok(true)
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_sync_operations(
        &self,
        conn: &Connection,
        device_id: &[u8; 16],
        key_epoch: u64,
        after_counter: u64,
        limit: usize,
    ) -> Result<Vec<SyncStoredOperationV1>, DatastoreError> {
        let key_epoch = i64::try_from(key_epoch)
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync operation epoch".into()))?;
        let after_counter = i64::try_from(after_counter)
            .map_err(|_| DatastoreError::InternalError("Invalid sync operation cursor".into()))?;
        let mut statement = conn.prepare_cached(
            "SELECT counter,operation_json,content_hash FROM sync_operations WHERE device_id = ?1 AND key_epoch = ?2 AND counter > ?3 ORDER BY counter LIMIT ?4",
        ).map_err(|_| DatastoreError::InternalError("Could not prepare sync operation listing".into()))?;
        let rows = statement.query_map(
            params![&device_id[..], key_epoch, after_counter, limit.clamp(1, 256) as i64],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)),
        ).map_err(|_| DatastoreError::InternalError("Could not list sync operations".into()))?;
        rows.map(|row| {
            let (counter, operation_json, content_hash) = row
                .map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?;
            Ok(SyncStoredOperationV1 {
                device_id: *device_id,
                counter: u64::try_from(counter)
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or_else(|| DatastoreError::InternalError("Stored sync operation is invalid".into()))?,
                key_epoch: u64::try_from(key_epoch)
                    .map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?,
                operation_json,
                content_hash: content_hash
                    .try_into()
                    .map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?,
            })
        }).collect()
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    fn all_sync_operations_for_epoch(
        &self,
        conn: &Connection,
        key_epoch: u64,
    ) -> Result<Vec<SyncOperationV1>, DatastoreError> {
        let epoch = i64::try_from(key_epoch)
            .ok().filter(|epoch| *epoch > 0)
            .ok_or_else(|| DatastoreError::InternalError("Invalid sync operation epoch".into()))?;
        let mut statement = conn.prepare_cached(
            "SELECT device_id,counter,operation_json,content_hash FROM sync_operations WHERE key_epoch = ?1 ORDER BY device_id,counter",
        ).map_err(|_| DatastoreError::InternalError("Sync operation log is unavailable".into()))?;
        let rows = statement.query_map([epoch], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        }).map_err(|_| DatastoreError::InternalError("Sync operation log is unavailable".into()))?;
        let records = rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?;
        records.into_iter().map(|(device, counter, json, stored_hash)| {
            let hash = digest(&SHA256, json.as_bytes());
            let device: [u8; 16] = device.try_into()
                .map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?;
            let counter = u64::try_from(counter).ok().filter(|counter| *counter > 0)
                .ok_or_else(|| DatastoreError::InternalError("Stored sync operation is invalid".into()))?;
            if stored_hash.as_slice() != hash.as_ref() {
                return Err(DatastoreError::InternalError("Stored sync operation hash is invalid".into()));
            }
            let operation: SyncOperationV1 = serde_json::from_str(&json)
                .map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?;
            operation.validate().map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?;
            let operation_device = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&operation.device_id)
                .map_err(|_| DatastoreError::InternalError("Stored sync operation is invalid".into()))?;
            if operation_device.as_slice() != &device[..] || operation.counter != counter {
                return Err(DatastoreError::InternalError("Stored sync operation identity is invalid".into()));
            }
            Ok(operation)
        }).collect()
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn record_sync_tombstone_ack(
        &self,
        conn: &Connection,
        origin_device_id: &[u8; 16],
        local_event_id: u64,
        tombstone_counter: u64,
        device_id: &[u8; 16],
        acknowledged_at: &str,
    ) -> Result<bool, DatastoreError> {
        // Callers must authenticate this acknowledgement against the verified device before storing it.
        if local_event_id == 0 || tombstone_counter == 0
            || DateTime::parse_from_rfc3339(acknowledged_at).is_err()
        {
            return Err(DatastoreError::InternalError("Invalid tombstone acknowledgement".into()));
        }
        let local_event_id = i64::try_from(local_event_id)
            .map_err(|_| DatastoreError::InternalError("Invalid tombstone acknowledgement".into()))?;
        let tombstone_counter = i64::try_from(tombstone_counter)
            .map_err(|_| DatastoreError::InternalError("Invalid tombstone acknowledgement".into()))?;
        with_savepoint(conn, "sync_tombstone_ack", || {
            let active = conn
                .query_row(
                    "SELECT 1 WHERE EXISTS(SELECT 1 FROM sync_device_identity i JOIN sync_key_material k ON k.id = 1 WHERE i.id = 1 AND i.device_id = ?1) OR EXISTS(SELECT 1 FROM sync_trusted_devices d JOIN sync_key_material k ON d.key_epoch = k.key_epoch WHERE d.device_id = ?1 AND d.revoked_at IS NULL)",
                    [&device_id[..]],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|_| DatastoreError::InternalError("Could not inspect tombstone acknowledgement device".into()))?;
            if active.is_none() {
                return Err(DatastoreError::InternalError("Tombstone acknowledgement is not from an active device".into()));
            }
            let inserted = conn
                .execute(
                    "INSERT OR IGNORE INTO sync_tombstone_acknowledgements(origin_device_id, local_event_id, tombstone_counter, device_id, acknowledged_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![&origin_device_id[..], local_event_id, tombstone_counter, &device_id[..], acknowledged_at],
                )
                .map_err(|_| DatastoreError::InternalError("Could not store tombstone acknowledgement".into()))?;
            Ok(inserted > 0)
        })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn list_local_sync_tombstone_acknowledgements(
        &self,
        conn: &Connection,
    ) -> Result<Vec<aw_sync_e2ee::SyncTombstoneAckV1>, DatastoreError> {
        let Some(identity) = self.get_sync_device_identity(conn)? else { return Ok(Vec::new()); };
        let mut statement = conn.prepare_cached(
            "SELECT origin_device_id,local_event_id,tombstone_counter FROM sync_tombstone_acknowledgements WHERE device_id = ?1 ORDER BY origin_device_id,local_event_id,tombstone_counter LIMIT 100001",
        ).map_err(|_| DatastoreError::InternalError("Tombstone acknowledgements are unavailable".into()))?;
        let rows = statement.query_map([&identity.device_id()[..]], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))
        }).map_err(|_| DatastoreError::InternalError("Tombstone acknowledgements are unavailable".into()))?;
        let rows = rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| DatastoreError::InternalError("Stored tombstone acknowledgement is invalid".into()))?;
        if rows.len() > 100_000 {
            return Err(DatastoreError::InternalError("Tombstone acknowledgement history exceeds its scan limit".into()));
        }
        rows.into_iter().map(|(origin, event_id, counter)| {
            let origin: [u8; 16] = origin.try_into()
                .map_err(|_| DatastoreError::InternalError("Stored tombstone acknowledgement is invalid".into()))?;
            Ok(aw_sync_e2ee::SyncTombstoneAckV1 {
                origin_device_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(origin),
                local_event_id: u64::try_from(event_id).ok().filter(|value| *value > 0)
                    .ok_or_else(|| DatastoreError::InternalError("Stored tombstone acknowledgement is invalid".into()))?,
                tombstone_counter: u64::try_from(counter).ok().filter(|value| *value > 0)
                    .ok_or_else(|| DatastoreError::InternalError("Stored tombstone acknowledgement is invalid".into()))?,
            })
        }).collect()
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn sync_tombstone_ack_state(
        &self,
        conn: &Connection,
        origin_device_id: &[u8; 16],
        local_event_id: u64,
        tombstone_counter: u64,
    ) -> Result<crate::SyncTombstoneAckStateV1, DatastoreError> {
        if local_event_id == 0 || tombstone_counter == 0 {
            return Err(DatastoreError::InternalError("Invalid tombstone identity".into()));
        }
        let mut active_statement = conn
            .prepare_cached("SELECT device_id FROM (SELECT i.device_id AS device_id FROM sync_device_identity i JOIN sync_key_material k ON k.id = 1 WHERE i.id = 1 UNION SELECT d.device_id AS device_id FROM sync_trusted_devices d JOIN sync_key_material k ON d.key_epoch = k.key_epoch WHERE d.revoked_at IS NULL) ORDER BY device_id")
            .map_err(|_| DatastoreError::InternalError("Could not query active sync devices".into()))?;
        let active_rows = active_statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| DatastoreError::InternalError("Could not query active sync devices".into()))?;
        let active_device_ids = active_rows
            .map(|row| {
                row.map_err(|_| DatastoreError::InternalError("Stored sync device is invalid".into()))?
                    .try_into()
                    .map_err(|_| DatastoreError::InternalError("Stored sync device is invalid".into()))
            })
            .collect::<Result<Vec<[u8; 16]>, DatastoreError>>()?;
        let local_event_id = i64::try_from(local_event_id)
            .map_err(|_| DatastoreError::InternalError("Invalid tombstone identity".into()))?;
        let tombstone_counter = i64::try_from(tombstone_counter)
            .map_err(|_| DatastoreError::InternalError("Invalid tombstone identity".into()))?;
        let mut ack_statement = conn
            .prepare_cached("SELECT device_id FROM sync_tombstone_acknowledgements WHERE origin_device_id = ?1 AND local_event_id = ?2 AND tombstone_counter = ?3")
            .map_err(|_| DatastoreError::InternalError("Could not query tombstone acknowledgements".into()))?;
        let ack_rows = ack_statement
            .query_map(params![&origin_device_id[..], local_event_id, tombstone_counter], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|_| DatastoreError::InternalError("Could not query tombstone acknowledgements".into()))?;
        let acknowledged_device_ids = ack_rows
            .map(|row| {
                row.map_err(|_| DatastoreError::InternalError("Stored tombstone acknowledgement is invalid".into()))?
                    .try_into()
                    .map_err(|_| DatastoreError::InternalError("Stored tombstone acknowledgement is invalid".into()))
            })
            .collect::<Result<Vec<[u8; 16]>, DatastoreError>>()?;
        Ok(crate::SyncTombstoneAckStateV1 { active_device_ids, acknowledged_device_ids })
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    pub fn can_collect_sync_tombstone(
        &self,
        conn: &Connection,
        origin_device_id: &[u8; 16],
        local_event_id: u64,
        tombstone_counter: u64,
    ) -> Result<bool, DatastoreError> {
        let state = self.sync_tombstone_ack_state(conn, origin_device_id, local_event_id, tombstone_counter)?;
        let active: BTreeSet<_> = state.active_device_ids.into_iter().collect();
        let acknowledged: BTreeSet<_> = state.acknowledged_device_ids.into_iter().collect();
        Ok(active.is_subset(&acknowledged))
    }

    pub fn store_egress_policy_state(
        &self,
        conn: &Connection,
        bundle: &SignedEgressPolicyBundleV1,
        user_policy: &EgressUserPolicyV1,
    ) -> Result<(), DatastoreError> {
        if bundle.schema_version != 1
            || bundle.bundle.validate().is_err()
            || EgressPolicyV1::from_bundle_and_user(&bundle.bundle, user_policy).is_err()
        {
            return Err(DatastoreError::InternalError("Invalid egress policy state".into()));
        }
        let state_json = serde_json::to_string(&StoredEgressPolicyState {
            bundle: bundle.clone(),
            user_policy: user_policy.clone(),
        })
            .map_err(|_| DatastoreError::InternalError("Invalid egress policy state".into()))?;
        with_savepoint(conn, "egress_policy_state", || {
            self.insert_key_value(conn, EGRESS_POLICY_STATE_KEY, &state_json)?;
            self.clear_egress_approvals(conn)
        })
    }

    pub fn get_egress_policy_state(
        &self,
        conn: &Connection,
    ) -> Result<Option<(SignedEgressPolicyBundleV1, EgressUserPolicyV1)>, DatastoreError> {
        let serialized = match self.get_key_value(conn, EGRESS_POLICY_STATE_KEY) {
            Ok(value) => value,
            Err(DatastoreError::NoSuchKey(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let state: StoredEgressPolicyState = serde_json::from_str(&serialized)
            .map_err(|_| DatastoreError::InternalError("Stored egress policy is invalid".into()))?;
        if state.bundle.bundle.validate().is_err()
            || EgressPolicyV1::from_bundle_and_user(&state.bundle.bundle, &state.user_policy).is_err()
        {
            return Err(DatastoreError::InternalError("Stored egress policy is invalid".into()));
        }
        Ok(Some((state.bundle, state.user_policy)))
    }

    pub fn get_egress_user_policy(&self, conn: &Connection) -> Result<EgressUserPolicyV1, DatastoreError> {
        if let Some((_, user_policy)) = self.get_egress_policy_state(conn)? {
            return Ok(user_policy);
        }
        let user_policy = match self.get_key_value(conn, EGRESS_USER_POLICY_KEY) {
            Ok(value) => serde_json::from_str(&value)
                .map_err(|_| DatastoreError::InternalError("Stored egress user policy is invalid".into()))?,
            Err(DatastoreError::NoSuchKey(_)) => empty_egress_user_policy(),
            Err(error) => return Err(error),
        };
        validate_egress_user_policy(&user_policy)?;
        Ok(user_policy)
    }

    pub fn store_egress_user_policy(
        &self,
        conn: &Connection,
        user_policy: &EgressUserPolicyV1,
    ) -> Result<(), DatastoreError> {
        validate_egress_user_policy(user_policy)?;
        if let Some((bundle, _)) = self.get_egress_policy_state(conn)? {
            return self.store_egress_policy_state(conn, &bundle, user_policy);
        }
        let serialized = serde_json::to_string(user_policy)
            .map_err(|_| DatastoreError::InternalError("Invalid egress user policy".into()))?;
        with_savepoint(conn, "egress_user_policy", || {
            self.insert_key_value(conn, EGRESS_USER_POLICY_KEY, &serialized)?;
            self.clear_egress_approvals(conn)
        })
    }

    fn get_or_create_egress_secret(&self, conn: &Connection, key: &str) -> Result<[u8; 32], DatastoreError> {
        match self.get_key_value(conn, key) {
            Ok(encoded) => decode_secret(&encoded),
            Err(DatastoreError::NoSuchKey(_)) => {
                let mut secret = [0_u8; 32];
                SystemRandom::new().fill(&mut secret)
                    .map_err(|_| DatastoreError::InternalError("Could not create local privacy key".into()))?;
                let encoded = encode_hex(&secret);
                self.insert_key_value(conn, key, &encoded)?;
                Ok(secret)
            }
            Err(error) => Err(error),
        }
    }

    pub fn create_egress_approval(
        &self,
        conn: &Connection,
        destination_id: &str,
        purpose_id: &str,
        retention_id: &str,
        policy_version: u64,
        scope: EgressApprovalScopeV1,
        payload_tag: &[u8; 32],
        expires_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) -> Result<String, DatastoreError> {
        if self.egress_kill_switch(conn)?
            || !valid_egress_identifier(destination_id)
            || !valid_egress_identifier(purpose_id)
            || !valid_egress_identifier(retention_id)
            || policy_version == 0
        {
            return Err(DatastoreError::InternalError("Egress approval is unavailable".into()));
        }
        let valid_expiry = match (scope, expires_at) {
            (EgressApprovalScopeV1::Once, Some(expiry)) => {
                expiry > created_at && expiry <= created_at + Duration::seconds(EGRESS_ONCE_MAX_SECONDS)
            }
            (EgressApprovalScopeV1::TimeLimited, Some(expiry)) => {
                expiry > created_at && expiry <= created_at + Duration::seconds(EGRESS_APPROVAL_MAX_SECONDS)
            }
            (EgressApprovalScopeV1::DestinationSpecific, None) => true,
            _ => false,
        };
        if !valid_expiry {
            return Err(DatastoreError::InternalError("Egress approval expiry is invalid".into()));
        }

        let mut id_bytes = [0_u8; 32];
        SystemRandom::new().fill(&mut id_bytes)
            .map_err(|_| DatastoreError::InternalError("Could not create local approval".into()))?;
        let id = encode_hex(&id_bytes);
        let scope_value = serde_json::to_string(&scope)
            .map_err(|_| DatastoreError::InternalError("Could not create local approval".into()))?;
        let policy_version = i64::try_from(policy_version)
            .map_err(|_| DatastoreError::InternalError("Could not create local approval".into()))?;
        let expiry = expires_at.map(|value| value.to_rfc3339());
        let uses_remaining = if scope == EgressApprovalScopeV1::Once { 1_i64 } else { -1_i64 };
        conn.execute(
            "INSERT INTO egress_approvals(id, destination_id, purpose_id, retention_id, policy_version, scope, payload_tag, expires_at, uses_remaining, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![id, destination_id, purpose_id, retention_id, policy_version, scope_value, payload_tag.as_slice(), expiry, uses_remaining, created_at.to_rfc3339()],
        ).map_err(|_| DatastoreError::InternalError("Could not create local approval".into()))?;
        Ok(id)
    }

    pub fn get_egress_approvals(
        &self,
        conn: &Connection,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<Vec<EgressApprovalV1>, DatastoreError> {
        let mut statement = conn.prepare_cached(
            "SELECT id, destination_id, purpose_id, retention_id, policy_version, scope, expires_at, created_at
             FROM egress_approvals
             WHERE (expires_at IS NULL OR expires_at > ?1) AND uses_remaining != 0
             ORDER BY created_at DESC LIMIT ?2",
        ).map_err(|_| DatastoreError::InternalError("Could not query egress approvals".into()))?;
        let rows = statement.query_map(params![now.to_rfc3339(), limit.min(100) as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?, row.get::<_, String>(7)?))
        }).map_err(|_| DatastoreError::InternalError("Could not query egress approvals".into()))?;
        rows.map(|row| {
            let (id, destination, purpose, retention, version, scope, expiry, created) = row
                .map_err(|_| DatastoreError::InternalError("Stored egress approval is invalid".into()))?;
            decode_egress_approval(id, destination, purpose, retention, version, scope, expiry, created)
        }).collect()
    }

    pub fn get_egress_approval(
        &self,
        conn: &Connection,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<EgressApprovalV1>, DatastoreError> {
        let row = conn.query_row(
            "SELECT id, destination_id, purpose_id, retention_id, policy_version, scope, expires_at, created_at
             FROM egress_approvals
             WHERE id = ?1 AND (expires_at IS NULL OR expires_at > ?2) AND uses_remaining != 0",
            params![id, now.to_rfc3339()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?, row.get::<_, String>(7)?)),
        ).optional().map_err(|_| DatastoreError::InternalError("Could not query egress approval".into()))?;
        row.map(|(id, destination, purpose, retention, version, scope, expiry, created)| {
            decode_egress_approval(id, destination, purpose, retention, version, scope, expiry, created)
        }).transpose()
    }

    pub fn consume_egress_approval(
        &self,
        conn: &Connection,
        id: &str,
        destination_id: &str,
        purpose_id: &str,
        retention_id: &str,
        policy_version: u64,
        payload_tag: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Result<EgressApprovalScopeV1, DatastoreError> {
        let invalid = || DatastoreError::InternalError("Egress approval is invalid or expired".into());
        if self.egress_kill_switch(conn)? { return Err(invalid()); }
        let (stored_destination, stored_purpose, stored_retention, stored_version, scope, stored_tag, expiry, uses):
            (String, String, String, i64, String, Vec<u8>, Option<String>, i64) = conn.query_row(
                "SELECT destination_id, purpose_id, retention_id, policy_version, scope, payload_tag, expires_at, uses_remaining FROM egress_approvals WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
            ).map_err(|_| invalid())?;
        let scope: EgressApprovalScopeV1 = serde_json::from_str(&scope).map_err(|_| invalid())?;
        let expiry = expiry.map(|value| DateTime::parse_from_rfc3339(&value).map(|date| date.with_timezone(&Utc)))
            .transpose().map_err(|_| invalid())?;
        let valid_uses = match scope {
            EgressApprovalScopeV1::Once => uses == 1 && expiry.is_some(),
            EgressApprovalScopeV1::TimeLimited => uses == -1 && expiry.is_some(),
            EgressApprovalScopeV1::DestinationSpecific => uses == -1 && expiry.is_none(),
        };
        if stored_destination != destination_id
            || stored_purpose != purpose_id
            || stored_retention != retention_id
            || u64::try_from(stored_version).ok() != Some(policy_version)
            || stored_tag.len() != payload_tag.len()
            || payload_tag.ct_eq(stored_tag.as_slice()).unwrap_u8() != 1
            || expiry.is_some_and(|value| now >= value)
            || !valid_uses
        {
            return Err(invalid());
        }
        if scope == EgressApprovalScopeV1::Once {
            conn.execute("DELETE FROM egress_approvals WHERE id = ?1", [id])
                .map_err(|_| invalid())?;
        }
        Ok(scope)
    }

    pub fn clear_egress_approvals(&self, conn: &Connection) -> Result<(), DatastoreError> {
        conn.execute("DELETE FROM egress_approvals", [])
            .map_err(|_| DatastoreError::InternalError("Could not clear egress approvals".into()))?;
        Ok(())
    }

    /// Renames a bucket from `old_id` to `new_id`.
    /// Events are left untouched because they reference the integer row ID, not the name.
    /// Returns `NoSuchBucket` if `old_id` does not exist, or `BucketAlreadyExists` if
    /// `new_id` is already taken.
    pub fn rename_bucket(
        &mut self,
        conn: &Connection,
        old_id: &str,
        new_id: &str,
    ) -> Result<(), DatastoreError> {
        if !self.buckets_cache.contains_key(old_id) {
            return Err(DatastoreError::NoSuchBucket(old_id.to_string()));
        }
        if self.buckets_cache.contains_key(new_id) {
            return Err(DatastoreError::BucketAlreadyExists(new_id.to_string()));
        }

        match conn.execute(
            "UPDATE buckets SET name = ?1 WHERE name = ?2",
            [new_id, old_id],
        ) {
            Ok(0) => Err(DatastoreError::NoSuchBucket(old_id.to_string())),
            Ok(_) => {
                info!("Renamed bucket '{}' to '{}'", old_id, new_id);
                // Update the in-memory cache: remove the old entry and re-insert under the new id.
                if let Some(mut bucket) = self.buckets_cache.remove(old_id) {
                    bucket.id = new_id.to_string();
                    self.buckets_cache.insert(new_id.to_string(), bucket);
                }
                Ok(())
            }
            Err(err) => Err(DatastoreError::InternalError(format!(
                "Failed to rename bucket '{}' to '{}': {err}",
                old_id, new_id
            ))),
        }
    }

    /// Migrates all buckets whose hostname is "unknown" or "Unknown" to `new_hostname`.
    /// Events are left untouched; only the bucket metadata is updated.
    /// Returns the number of buckets that were updated.
    pub fn migrate_hostname(
        &mut self,
        conn: &Connection,
        new_hostname: &str,
    ) -> Result<usize, DatastoreError> {
        info!(
            "Migrating hostname from 'unknown'/'Unknown' to '{}'",
            new_hostname
        );

        let updated = match conn.execute(
            "UPDATE buckets SET hostname = ?1 WHERE hostname = 'unknown' OR hostname = 'Unknown'",
            [new_hostname],
        ) {
            Ok(n) => n,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to migrate hostname: {err}"
                )))
            }
        };

        if updated > 0 {
            info!("Migrated hostname for {} bucket(s)", updated);
            // Refresh the in-memory cache so callers see the new hostnames immediately.
            self.get_stored_buckets(conn)?;
        } else {
            info!("No buckets with hostname 'unknown'/'Unknown' found; nothing to migrate");
        }

        Ok(updated)
    }

    /// Migrates all buckets whose name starts with `aw-watcher-android-test` to use
    /// `aw-watcher-android` instead.  This covers the old debug-build bucket naming
    /// convention (e.g. `aw-watcher-android-test_hostname` → `aw-watcher-android_hostname`).
    /// Events are left untouched; only the bucket metadata is updated.
    /// Returns the number of buckets that were migrated.
    /// Note: if a UNIQUE constraint violation occurs on any single row, `UPDATE OR IGNORE`
    /// will skip conflicting rows instead of aborting the entire batch.
    pub fn migrate_test_bucket_names(
        &mut self,
        conn: &Connection,
    ) -> Result<usize, DatastoreError> {
        info!("Migrating 'aw-watcher-android-test' bucket names to 'aw-watcher-android'");

        let updated = match conn.execute(
            "UPDATE OR IGNORE buckets SET name = 'aw-watcher-android' || SUBSTR(name, LENGTH('aw-watcher-android-test') + 1) \
             WHERE name LIKE 'aw-watcher-android-test%'",
            [],
        ) {
            Ok(n) => n,
            Err(err) => {
                return Err(DatastoreError::InternalError(format!(
                    "Failed to migrate test bucket names: {err}"
                )))
            }
        };

        if updated > 0 {
            info!("Migrated {} 'aw-watcher-android-test' bucket(s)", updated);
            // Refresh the in-memory cache so callers see the new names immediately.
            self.get_stored_buckets(conn)?;
        } else {
            info!("No 'aw-watcher-android-test' buckets found; nothing to migrate");
        }

        Ok(updated)
    }
}

#[cfg(test)]
mod egress_migration_tests {
    use super::*;

    #[test]
    fn v6_migrations_add_receipts_and_approvals_and_preserve_settings() {
        let conn = Connection::open_in_memory().unwrap();
        _create_tables(&conn, 0, false);
        conn.execute(
            "INSERT INTO key_value(key, value, last_modified) VALUES ('settings.keep', 'value', 1)",
            [],
        ).unwrap();
        conn.execute_batch("DROP TABLE egress_approvals; DROP TABLE egress_receipts; PRAGMA user_version = 6;").unwrap();

        let _datastore = DatastoreInstance::new(&conn, true, false).unwrap();
        let version = _get_db_version(&conn);
        let setting: String = conn.query_row(
            "SELECT value FROM key_value WHERE key = 'settings.keep'",
            [],
            |row| row.get(0),
        ).unwrap();
        let table_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'egress_receipts'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(version, 12);
        assert_eq!(setting, "value");
        assert_eq!(table_count, 1);
        let approvals: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'egress_approvals'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(approvals, 1);
    }
}

#[cfg(test)]
mod sync_v12_migration_tests {
    use super::*;

    #[test]
    fn schema_v9_upgrade_preserves_activity_and_requires_peer_repair() {
        let conn = Connection::open_in_memory().unwrap();
        _migrate_v0_to_v1(&conn);
        _migrate_v1_to_v2(&conn);
        _migrate_v2_to_v3(&conn);
        _migrate_v3_to_v4(&conn);
        _migrate_v4_to_v5(&conn);
        _migrate_v5_to_v6(&conn);
        _migrate_v6_to_v7(&conn);
        _migrate_v7_to_v8(&conn);
        _migrate_v8_to_v9(&conn);

        conn.execute(
            "INSERT INTO buckets(id,name,type,client,hostname,created,data) VALUES (1,'aw-app-host','app','PeakActivity','host','2026-09-23T00:00:00Z','{}')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO events(id,bucketrow,starttime,endtime,data) VALUES (1,1,100,200,'{\"app\":\"Editor\"}')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO sync_device_identity(id,device_id,private_key) VALUES (1,?1,?2)",
            params![&[1u8; 16][..], &[2u8; 32][..]],
        ).unwrap();
        conn.execute(
            "INSERT INTO sync_trusted_devices(device_id,x25519_public_key,paired_at,revoked_at,key_epoch) VALUES (?1,?2,'2026-09-23T00:00:00Z',NULL,1)",
            params![&[3u8; 16][..], &[4u8; 32][..]],
        ).unwrap();
        conn.execute(
            "INSERT INTO sync_runtime_control(id,enabled,destination_id,purpose_id) VALUES (1,1,'legacy-destination','sync-object-v1')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO sync_manifest_heads(vault_id,revision,head_hash) VALUES (?1,1,?2)",
            params![&[5u8; 16][..], &[6u8; 32][..]],
        ).unwrap();

        DatastoreInstance::new(&conn, true, false).unwrap();

        assert_eq!(_get_db_version(&conn), 12);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM buckets", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        let signing_seed: Option<Vec<u8>> = conn.query_row(
            "SELECT signing_seed FROM sync_device_identity WHERE id = 1",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(signing_seed.is_none());
        let peer_signing_key: Option<Vec<u8>> = conn.query_row(
            "SELECT ed25519_public_key FROM sync_trusted_devices WHERE device_id = ?1",
            [&[3u8; 16][..]],
            |row| row.get(0),
        ).unwrap();
        assert!(peer_signing_key.is_none());
        let (enabled, destination): (i64, Option<String>) = conn.query_row(
            "SELECT enabled,destination_id FROM sync_runtime_control WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(enabled, 0);
        assert_eq!(destination, None);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM sync_manifest_heads", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM sync_stream_heads", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM sync_bucket_mappings", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'plugin_storage'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'plugin_events'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    }

    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    #[test]
    fn encrypted_v9_upgrade_generates_a_local_signing_seed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "key", "encrypted-migration-test-key").unwrap();
        _migrate_v0_to_v1(&conn);
        _migrate_v1_to_v2(&conn);
        _migrate_v2_to_v3(&conn);
        _migrate_v3_to_v4(&conn);
        _migrate_v4_to_v5(&conn);
        _migrate_v5_to_v6(&conn);
        _migrate_v6_to_v7(&conn);
        _migrate_v7_to_v8(&conn);
        _migrate_v8_to_v9(&conn);
        conn.execute(
            "INSERT INTO sync_device_identity(id,device_id,private_key) VALUES (1,?1,?2)",
            params![&[1u8; 16][..], &[2u8; 32][..]],
        ).unwrap();

        DatastoreInstance::new(&conn, true, true).unwrap();

        let signing_seed: Vec<u8> = conn.query_row(
            "SELECT signing_seed FROM sync_device_identity WHERE id = 1",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(signing_seed.len(), 32);
        assert_ne!(signing_seed, [0u8; 32]);
    }
}
