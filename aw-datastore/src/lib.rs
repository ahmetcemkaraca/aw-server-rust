#[macro_use]
extern crate log;

use std::fmt;

#[macro_export]
macro_rules! json_map {
    { $( $key:literal : $value:expr),* } => {{
        use serde_json::Value;
        use serde_json::map::Map;
        #[allow(unused_mut)]
        let mut map : Map<String, Value> = Map::new();
        $(
          map.insert( $key.to_string(), json!($value) );
        )*
        map
    }};
}

mod datastore;
mod legacy_import;
mod privacy_filter;
mod worker;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
pub mod vault;

pub use self::datastore::{DatastoreInstance, EventCorrection};
pub use self::worker::{Datastore, EgressLease, ImportSummary};

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone)]
pub struct SyncDeviceIdentity {
    device_id: [u8; 16],
    private_key: zeroize::Zeroizing<[u8; 32]>,
    signing_seed: zeroize::Zeroizing<[u8; 32]>,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl SyncDeviceIdentity {
    pub fn new(
        device_id: [u8; 16],
        private_key: zeroize::Zeroizing<[u8; 32]>,
        signing_seed: zeroize::Zeroizing<[u8; 32]>,
    ) -> Self {
        Self { device_id, private_key, signing_seed }
    }

    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub fn signing_seed(&self) -> &[u8; 32] {
        &self.signing_seed
    }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl fmt::Debug for SyncDeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncDeviceIdentity")
            .field("device_id", &self.device_id)
            .field("private_key", &"<redacted>")
            .field("signing_seed", &"<redacted>")
            .finish()
    }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone)]
pub struct SyncKeyMaterial {
    account_root_key: zeroize::Zeroizing<[u8; 32]>,
    vault_id: [u8; 16],
    key_epoch: u64,
    wrapped_nonce: [u8; 24],
    wrapped_ciphertext: [u8; 48],
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, PartialEq)]
pub struct SyncSnapshotV1 {
    pub snapshot_id: [u8; 16],
    pub envelopes: Vec<aw_models::SyncEnvelopeV1>,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl SyncSnapshotV1 {
    pub fn new(snapshot_id: [u8; 16], envelopes: Vec<aw_models::SyncEnvelopeV1>) -> Self {
        Self { snapshot_id, envelopes }
    }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncTombstoneIdentityV1 {
    pub origin_device_id: [u8; 16],
    pub local_event_id: u64,
    pub tombstone_counter: u64,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncTombstoneAckStateV1 {
    pub active_device_ids: Vec<[u8; 16]>,
    pub acknowledged_device_ids: Vec<[u8; 16]>,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SyncObjectHistoryV1 {
    pub object_id: String,
    pub action: String,
    pub occurred_at: String,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, PartialEq)]
pub struct SyncObjectPageV1 {
    pub objects: Vec<aw_models::SyncEnvelopeV1>,
    pub next_cursor: Option<String>,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncEgressConsentV1 {
    pub destination_id: String,
    pub purpose_id: String,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl SyncKeyMaterial {
    pub fn new(
        account_root_key: zeroize::Zeroizing<[u8; 32]>,
        vault_id: [u8; 16],
        key_epoch: u64,
        wrapped_nonce: [u8; 24],
        wrapped_ciphertext: [u8; 48],
    ) -> Self {
        Self { account_root_key, vault_id, key_epoch, wrapped_nonce, wrapped_ciphertext }
    }

    pub fn account_root_key(&self) -> &[u8; 32] { &self.account_root_key }
    pub fn vault_id(&self) -> &[u8; 16] { &self.vault_id }
    pub fn key_epoch(&self) -> u64 { self.key_epoch }
    pub fn wrapped_nonce(&self) -> &[u8; 24] { &self.wrapped_nonce }
    pub fn wrapped_ciphertext(&self) -> &[u8; 48] { &self.wrapped_ciphertext }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl fmt::Debug for SyncKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncKeyMaterial")
            .field("account_root_key", &"<redacted>")
            .field("vault_id", &self.vault_id)
            .field("key_epoch", &self.key_epoch)
            .field("wrapped_nonce", &self.wrapped_nonce)
            .field("wrapped_ciphertext", &"<ciphertext>")
            .finish()
    }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncTrustedDevice {
    pub device_id: [u8; 16],
    pub x25519_public_key: [u8; 32],
    pub ed25519_public_key: Option<[u8; 32]>,
    pub paired_at: String,
    pub revoked_at: Option<String>,
    pub key_epoch: u64,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncStoredOperationV1 {
    pub device_id: [u8; 16],
    pub counter: u64,
    pub key_epoch: u64,
    pub operation_json: String,
    pub content_hash: [u8; 32],
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecoveryBucketMappingV1 {
    pub sync_bucket_id: [u8; 16],
    pub local_bucket_id: String,
    pub descriptor: aw_models::SyncBucketDescriptorV1,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecoveryEventMappingV1 {
    pub origin_device_id: [u8; 16],
    pub origin_event_id: u64,
    pub sync_bucket_id: [u8; 16],
    pub local_bucket_id: String,
    pub local_event_id: Option<u64>,
    pub deleted: bool,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecoveryTrustedDeviceV1 {
    pub device_id: [u8; 16],
    pub x25519_public_key: [u8; 32],
    pub ed25519_public_key: [u8; 32],
    pub paired_at: String,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecoveryStreamHeadV1 {
    pub device_id: [u8; 16],
    pub revision: u64,
    pub head_hash: [u8; 32],
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecoveryCounterV1 {
    pub device_id: [u8; 16],
    pub last_counter: u64,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecoveryTombstoneAckV1 {
    pub origin_device_id: [u8; 16],
    pub local_event_id: u64,
    pub tombstone_counter: u64,
    pub device_id: [u8; 16],
    pub acknowledged_at: String,
}

/// Public sync continuity data stored inside the encrypted recovery snapshot.
/// Device private keys deliberately have no field in this type.
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncRecoveryStateV1 {
    pub schema_version: u32,
    pub key_epoch: u64,
    pub baseline_complete: bool,
    pub bucket_mappings: Vec<SyncRecoveryBucketMappingV1>,
    pub event_mappings: Vec<SyncRecoveryEventMappingV1>,
    pub trusted_devices: Vec<SyncRecoveryTrustedDeviceV1>,
    pub operations: Vec<SyncStoredOperationV1>,
    pub stream_heads: Vec<SyncRecoveryStreamHeadV1>,
    pub counters: Vec<SyncRecoveryCounterV1>,
    pub tombstone_acknowledgements: Vec<SyncRecoveryTombstoneAckV1>,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SyncBaselineProgressV1 {
    pub key_epoch: u64,
    pub baseline_max_event_id: u64,
    pub baseline_cursor: u64,
    pub complete: bool,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone)]
pub struct SyncApplyBatchV1 {
    pub manifest: aw_sync_e2ee::SyncManifestV1,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl fmt::Debug for SyncApplyBatchV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncApplyBatchV1")
            .field("key_epoch", &self.manifest.key_epoch)
            .field("next_revision", &self.manifest.revision)
            .field("operations", &"<encrypted-vault data>")
            .finish()
    }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl fmt::Debug for SyncStoredOperationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncStoredOperationV1")
            .field("device_id", &self.device_id)
            .field("counter", &self.counter)
            .field("key_epoch", &self.key_epoch)
            .field("operation_json", &"<encrypted-vault data>")
            .field("content_hash", &"<redacted>")
            .finish()
    }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncDeviceAccessEvent {
    pub device_id: [u8; 16],
    pub action: String,
    pub occurred_at: String,
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncManifestHeadV1 {
    pub revision: u64,
    pub head_hash: [u8; 32],
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
impl SyncManifestHeadV1 {
    pub fn genesis() -> Self { Self { revision: 0, head_hash: [0; 32] } }
    pub fn new(revision: u64, head_hash: [u8; 32]) -> Self { Self { revision, head_hash } }
}

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncHeadCommitV1 {
    Advanced,
    Duplicate,
}

pub struct EgressSecrets {
    alias_secret: zeroize::Zeroizing<[u8; 32]>,
    approval_secret: zeroize::Zeroizing<[u8; 32]>,
}

impl EgressSecrets {
    pub(crate) fn new(alias_secret: [u8; 32], approval_secret: [u8; 32]) -> Self {
        Self {
            alias_secret: zeroize::Zeroizing::new(alias_secret),
            approval_secret: zeroize::Zeroizing::new(approval_secret),
        }
    }

    pub fn alias_secret(&self) -> &[u8] { &self.alias_secret[..] }

    pub fn approval_secret(&self) -> &[u8] { &self.approval_secret[..] }
}

impl fmt::Debug for EgressSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressSecrets")
            .field("alias_secret", &"<redacted>")
            .field("approval_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub enum DatastoreMethod {
    Memory(),
    File(String),
    /// Encrypted SQLite file using SQLCipher. Only available with the
    /// `encryption` or `encryption-vendored` feature flags.
    #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
    FileEncrypted(String, zeroize::Zeroizing<String>), // (path, key)
}

impl fmt::Debug for DatastoreMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatastoreMethod::Memory() => write!(f, "Memory()"),
            DatastoreMethod::File(p) => write!(f, "File({p:?})"),
            #[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
            DatastoreMethod::FileEncrypted(p, _) => write!(f, "FileEncrypted({p:?}, <redacted>)"),
        }
    }
}

/* TODO: Implement this as a proper error */
#[derive(Debug, Clone)]
pub enum DatastoreError {
    Locked,
    NoSuchEvent(String),
    InvalidImport(String),
    InvalidTimeRange,
    InvalidCorrection(String),
    InvalidRetentionPolicy,
    NoSuchBucket(String),
    BucketAlreadyExists(String),
    NoSuchKey(String),
    MpscError,
    InternalError(String),
    // Errors specific to when migrate is disabled
    Uninitialized(String),
    OldDbVersion(String),
}
