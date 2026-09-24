use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aw_models::{
    DevicePublicIdentityV1, Event, SyncBucketDescriptorV1, SyncChunkHeaderV1, SyncEnvelopeV1,
    SyncOperationKindV1, SYNC_ID_BYTES, SYNC_MAX_CHUNK_BYTES,
    SYNC_SCHEMA_VERSION_V1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{decrypt_chunk, encrypt_chunk, DeviceIdentityV1, SyncErrorV1, VaultDataKeyV1};

const MAX_OPERATIONS: usize = 10_000;
const MAX_MERGE_HISTORY: usize = 100_000;
const MAX_SQLITE_INTEGER: u64 = i64::MAX as u64;
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"PeakActivity-Sync-Manifest-Sign-v1\0";

pub fn encode_sync_data_field_v1(key: &str) -> String {
    let mut field = String::from("data:");
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            field.push(char::from(byte));
        } else {
            field.push_str(&format!("%{byte:02X}"));
        }
    }
    field
}

pub fn decode_sync_data_field_v1(field: &str) -> Option<String> {
    let encoded = field.strip_prefix("data:")?;
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut encoded = encoded.bytes();
    while let Some(byte) = encoded.next() {
        if byte == b'%' {
            let high = (encoded.next()? as char).to_digit(16)? as u8;
            let low = (encoded.next()? as char).to_digit(16)? as u8;
            bytes.push((high << 4) | low);
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            bytes.push(byte);
        } else {
            return None;
        }
    }
    String::from_utf8(bytes).ok()
}

pub fn encrypt_manifest(
    key: &VaultDataKeyV1,
    header: &SyncChunkHeaderV1,
    manifest: &SyncManifestV1,
) -> Result<SyncEnvelopeV1, SyncErrorV1> {
    manifest.validate().map_err(|_| SyncErrorV1::InvalidManifest)?;
    if manifest.key_epoch != header.key_epoch {
        return Err(SyncErrorV1::InvalidManifest);
    }
    let plaintext = Zeroizing::new(
        serde_json::to_vec(manifest).map_err(|_| SyncErrorV1::InvalidManifest)?,
    );
    encrypt_chunk(key, header, &plaintext)
}

pub fn decrypt_manifest(
    key: &VaultDataKeyV1,
    envelope: &SyncEnvelopeV1,
) -> Result<SyncManifestV1, SyncErrorV1> {
    let plaintext = decrypt_chunk(key, envelope)?;
    let manifest: SyncManifestV1 =
        serde_json::from_slice(&plaintext).map_err(|_| SyncErrorV1::InvalidManifest)?;
    manifest.validate().map_err(|_| SyncErrorV1::InvalidManifest)?;
    if manifest.key_epoch != envelope.key_epoch {
        return Err(SyncErrorV1::InvalidManifest);
    }
    Ok(manifest)
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncOperationV1 {
    pub schema_version: u32,
    pub device_id: String,
    pub counter: u64,
    pub origin_device_id: String,
    pub local_event_id: Option<u64>,
    pub sync_bucket_id: Option<String>,
    pub bucket_descriptor: Option<SyncBucketDescriptorV1>,
    pub kind: SyncOperationKindV1,
    pub policy_version: Option<u64>,
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncTombstoneAckV1 {
    pub origin_device_id: String,
    pub local_event_id: u64,
    pub tombstone_counter: u64,
}

impl SyncTombstoneAckV1 {
    pub fn validate(&self) -> Result<(), MergeErrorV1> {
        decode_id(&self.origin_device_id)?;
        if self.local_event_id == 0 || self.local_event_id > MAX_SQLITE_INTEGER
            || self.tombstone_counter == 0 || self.tombstone_counter > MAX_SQLITE_INTEGER
        {
            return Err(MergeErrorV1::InvalidOperation);
        }
        Ok(())
    }
}

impl SyncOperationV1 {
    pub fn validate(&self) -> Result<(), MergeErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1
            || self.counter == 0
            || self.counter > MAX_SQLITE_INTEGER
        {
            return Err(MergeErrorV1::InvalidOperation);
        }
        let device_id = decode_id(&self.device_id)?;
        let origin_device_id = decode_id(&self.origin_device_id)?;
        if self.fields.len() > 10_000
            || self.fields.keys().any(|key| {
                key.is_empty()
                    || key.len() > SYNC_MAX_CHUNK_BYTES
                    || (key.starts_with("data:") && decode_sync_data_field_v1(key).is_none())
                    || (!key.starts_with("data:") && key.chars().any(char::is_control))
            })
            || serde_json::to_vec(&self.fields)
                .map_err(|_| MergeErrorV1::InvalidOperation)?
                .len()
                > SYNC_MAX_CHUNK_BYTES
        {
            return Err(MergeErrorV1::InvalidOperation);
        }
        match &self.kind {
            SyncOperationKindV1::Upsert | SyncOperationKindV1::Correction => {
                if self.local_event_id.filter(|id| *id > 0 && *id <= MAX_SQLITE_INTEGER).is_none()
                    || self.policy_version.is_some()
                    || self.fields.is_empty()
                    || self.sync_bucket_id.as_deref().and_then(|id| decode_id(id).ok()).is_none()
                    || (self.kind == SyncOperationKindV1::Upsert) != self.bucket_descriptor.is_some()
                {
                    return Err(MergeErrorV1::InvalidOperation);
                }
                if let Some(descriptor) = &self.bucket_descriptor {
                    descriptor.validate().map_err(|_| MergeErrorV1::InvalidOperation)?;
                }
            }
            SyncOperationKindV1::Tombstone => {
                if self.local_event_id.filter(|id| *id > 0 && *id <= MAX_SQLITE_INTEGER).is_none()
                    || self.policy_version.is_some()
                    || !self.fields.is_empty()
                    || self.sync_bucket_id.as_deref().and_then(|id| decode_id(id).ok()).is_none()
                    || self.bucket_descriptor.is_some()
                {
                    return Err(MergeErrorV1::InvalidOperation);
                }
            }
            SyncOperationKindV1::PolicyChange => {
                if self.local_event_id.is_some()
                    || self.policy_version.filter(|version| *version > 0).is_none()
                    || self.fields.is_empty()
                    || device_id != origin_device_id
                    || self.sync_bucket_id.is_some()
                    || self.bucket_descriptor.is_some()
                {
                    return Err(MergeErrorV1::InvalidOperation);
                }
            }
        }
        Ok(())
    }
}

pub fn create_event_upsert(
    device_id: [u8; SYNC_ID_BYTES],
    counter: u64,
    sync_bucket_id: [u8; SYNC_ID_BYTES],
    bucket_descriptor: SyncBucketDescriptorV1,
    event: &Event,
) -> Result<SyncOperationV1, MergeErrorV1> {
    let local_event_id = event
        .id
        .filter(|id| *id > 0)
        .and_then(|id| u64::try_from(id).ok())
        .ok_or(MergeErrorV1::InvalidOperation)?;
    let duration_ns = event
        .duration
        .num_nanoseconds()
        .filter(|duration| *duration >= 0)
        .ok_or(MergeErrorV1::InvalidOperation)?;
    let mut fields = event.data.iter()
        .map(|(key, value)| (encode_sync_data_field_v1(key), value.clone()))
        .collect::<BTreeMap<_, _>>();
    fields.insert("duration_ns".into(), json!(duration_ns));
    fields.insert("timestamp".into(), json!(event.timestamp.to_rfc3339()));
    event_operation(
        device_id,
        counter,
        device_id,
        local_event_id,
        Some(sync_bucket_id),
        Some(bucket_descriptor),
        SyncOperationKindV1::Upsert,
        fields,
    )
}

pub fn create_event_correction(
    device_id: [u8; SYNC_ID_BYTES],
    counter: u64,
    origin_device_id: [u8; SYNC_ID_BYTES],
    local_event_id: u64,
    sync_bucket_id: [u8; SYNC_ID_BYTES],
    fields: BTreeMap<String, Value>,
) -> Result<SyncOperationV1, MergeErrorV1> {
    event_operation(
        device_id,
        counter,
        origin_device_id,
        local_event_id,
        Some(sync_bucket_id),
        None,
        SyncOperationKindV1::Correction,
        fields,
    )
}

pub fn create_event_tombstone(
    device_id: [u8; SYNC_ID_BYTES],
    counter: u64,
    origin_device_id: [u8; SYNC_ID_BYTES],
    local_event_id: u64,
    sync_bucket_id: [u8; SYNC_ID_BYTES],
) -> Result<SyncOperationV1, MergeErrorV1> {
    event_operation(
        device_id,
        counter,
        origin_device_id,
        local_event_id,
        Some(sync_bucket_id),
        None,
        SyncOperationKindV1::Tombstone,
        BTreeMap::new(),
    )
}

pub fn create_policy_change(
    device_id: [u8; SYNC_ID_BYTES],
    counter: u64,
    policy_version: u64,
    fields: BTreeMap<String, Value>,
) -> Result<SyncOperationV1, MergeErrorV1> {
    let operation = SyncOperationV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        device_id: URL_SAFE_NO_PAD.encode(device_id),
        counter,
        origin_device_id: URL_SAFE_NO_PAD.encode(device_id),
        local_event_id: None,
        sync_bucket_id: None,
        bucket_descriptor: None,
        kind: SyncOperationKindV1::PolicyChange,
        policy_version: Some(policy_version),
        fields,
    };
    operation.validate()?;
    Ok(operation)
}

fn event_operation(
    device_id: [u8; SYNC_ID_BYTES],
    counter: u64,
    origin_device_id: [u8; SYNC_ID_BYTES],
    local_event_id: u64,
    sync_bucket_id: Option<[u8; SYNC_ID_BYTES]>,
    bucket_descriptor: Option<SyncBucketDescriptorV1>,
    kind: SyncOperationKindV1,
    fields: BTreeMap<String, Value>,
) -> Result<SyncOperationV1, MergeErrorV1> {
    let operation = SyncOperationV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        device_id: URL_SAFE_NO_PAD.encode(device_id),
        counter,
        origin_device_id: URL_SAFE_NO_PAD.encode(origin_device_id),
        local_event_id: Some(local_event_id),
        sync_bucket_id: sync_bucket_id.map(|id| URL_SAFE_NO_PAD.encode(id)),
        bucket_descriptor,
        kind,
        policy_version: None,
        fields,
    };
    operation.validate()?;
    Ok(operation)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncManifestV1 {
    pub schema_version: u32,
    pub key_epoch: u64,
    pub writer_device_id: String,
    pub revision: u64,
    pub parent_hash: String,
    pub operations: Vec<SyncOperationV1>,
    #[serde(default)]
    pub tombstone_acknowledgements: Vec<SyncTombstoneAckV1>,
    pub head_hash: String,
    pub signature: String,
}

#[derive(Serialize)]
struct ManifestHashInputV1<'a> {
    schema_version: u32,
    key_epoch: u64,
    writer_device_id: &'a str,
    revision: u64,
    parent_hash: &'a str,
    operations: &'a [SyncOperationV1],
    tombstone_acknowledgements: &'a [SyncTombstoneAckV1],
}

impl SyncManifestV1 {
    pub fn new_signed(
        writer: &DeviceIdentityV1,
        vault_id: [u8; SYNC_ID_BYTES],
        key_epoch: u64,
        revision: u64,
        parent_hash: [u8; 32],
        operations: Vec<SyncOperationV1>,
    ) -> Result<Self, SyncErrorV1> {
        Self::new_signed_with_tombstone_acks(
            writer, vault_id, key_epoch, revision, parent_hash, operations, Vec::new(),
        )
    }

    pub fn new_signed_with_tombstone_acks(
        writer: &DeviceIdentityV1,
        vault_id: [u8; SYNC_ID_BYTES],
        key_epoch: u64,
        revision: u64,
        parent_hash: [u8; 32],
        operations: Vec<SyncOperationV1>,
        tombstone_acknowledgements: Vec<SyncTombstoneAckV1>,
    ) -> Result<Self, SyncErrorV1> {
        if key_epoch == 0 || key_epoch > MAX_SQLITE_INTEGER || revision == 0 || revision > MAX_SQLITE_INTEGER {
            return Err(SyncErrorV1::InvalidManifest);
        }
        let operations = canonical_operations(operations, MAX_OPERATIONS).map_err(|_| SyncErrorV1::InvalidManifest)?;
        let tombstone_acknowledgements = canonical_tombstone_acknowledgements(tombstone_acknowledgements)
            .map_err(|_| SyncErrorV1::InvalidManifest)?;
        let writer_device_id = URL_SAFE_NO_PAD.encode(writer.device_id_bytes());
        if operations.iter().any(|operation| operation.device_id != writer_device_id) {
            return Err(SyncErrorV1::InvalidManifest);
        }
        let parent_hash = URL_SAFE_NO_PAD.encode(parent_hash);
        let mut manifest = Self {
            schema_version: SYNC_SCHEMA_VERSION_V1,
            key_epoch,
            writer_device_id,
            revision,
            parent_hash,
            operations,
            tombstone_acknowledgements,
            head_hash: String::new(),
            signature: String::new(),
        };
        manifest.head_hash = URL_SAFE_NO_PAD.encode(
            manifest.calculate_hash().map_err(|_| SyncErrorV1::InvalidManifest)?,
        );
        manifest.signature = URL_SAFE_NO_PAD.encode(writer.sign_manifest_bytes(
            &manifest.signing_bytes(&vault_id).map_err(|_| SyncErrorV1::InvalidManifest)?,
        ));
        manifest.validate().map_err(|_| SyncErrorV1::InvalidManifest)?;
        Ok(manifest)
    }

    pub fn verify_signature(
        &self,
        public_identity: &DevicePublicIdentityV1,
        vault_id: &[u8; SYNC_ID_BYTES],
    ) -> Result<(), SyncErrorV1> {
        self.validate().map_err(|_| SyncErrorV1::InvalidManifest)?;
        public_identity.validate().map_err(|_| SyncErrorV1::InvalidSignature)?;
        if self.writer_device_id != public_identity.device_id {
            return Err(SyncErrorV1::InvalidSignature);
        }
        let public_key = URL_SAFE_NO_PAD
            .decode(&public_identity.ed25519_public_key)
            .map_err(|_| SyncErrorV1::InvalidSignature)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| SyncErrorV1::InvalidSignature)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(
                &self.signing_bytes(vault_id)
                    .map_err(|_| SyncErrorV1::InvalidManifest)?,
                &signature,
            )
            .map_err(|_| SyncErrorV1::InvalidSignature)
    }

    pub fn validate(&self) -> Result<(), MergeErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1
            || self.key_epoch == 0
            || self.key_epoch > MAX_SQLITE_INTEGER
            || self.revision == 0
            || self.revision > MAX_SQLITE_INTEGER
        {
            return Err(MergeErrorV1::InvalidManifest);
        }
        decode_id(&self.writer_device_id)?;
        decode_hash(&self.parent_hash)?;
        decode_hash(&self.head_hash)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|_| MergeErrorV1::InvalidManifest)?;
        if signature.len() != 64 || self.operations.iter().any(|op| op.device_id != self.writer_device_id) {
            return Err(MergeErrorV1::InvalidManifest);
        }
        if self.operations.len() > MAX_OPERATIONS
            || canonical_operations(self.operations.clone(), MAX_OPERATIONS)? != self.operations
            || self.tombstone_acknowledgements.len() > MAX_OPERATIONS
            || canonical_tombstone_acknowledgements(self.tombstone_acknowledgements.clone())? != self.tombstone_acknowledgements
            || serde_json::to_vec(self)
                .map_err(|_| MergeErrorV1::InvalidManifest)?
                .len()
                > SYNC_MAX_CHUNK_BYTES
        {
            return Err(MergeErrorV1::InvalidManifest);
        }
        if URL_SAFE_NO_PAD.encode(self.calculate_hash()?) != self.head_hash {
            return Err(MergeErrorV1::InvalidManifest);
        }
        Ok(())
    }

    pub fn advance(&self, current: &SyncHeadV1) -> Result<ManifestDecisionV1, MergeErrorV1> {
        self.validate()?;
        let new_hash = decode_hash(&self.head_hash)?;
        if self.revision == current.revision {
            return if new_hash == current.head_hash {
                Ok(ManifestDecisionV1::Duplicate)
            } else {
                Err(MergeErrorV1::RevisionFork)
            };
        }
        if self.revision < current.revision {
            return Err(MergeErrorV1::Rollback);
        }
        if self.revision != current.revision.saturating_add(1) {
            return Err(MergeErrorV1::RevisionGap);
        }
        if decode_hash(&self.parent_hash)? != current.head_hash {
            return Err(MergeErrorV1::InvalidAncestry);
        }
        Ok(ManifestDecisionV1::Advanced(SyncHeadV1 {
            revision: self.revision,
            head_hash: new_hash,
        }))
    }

    fn calculate_hash(&self) -> Result<[u8; 32], MergeErrorV1> {
        let bytes = serde_json::to_vec(&ManifestHashInputV1 {
            schema_version: self.schema_version,
            key_epoch: self.key_epoch,
            writer_device_id: &self.writer_device_id,
            revision: self.revision,
            parent_hash: &self.parent_hash,
            operations: &self.operations,
            tombstone_acknowledgements: &self.tombstone_acknowledgements,
        })
        .map_err(|_| MergeErrorV1::InvalidManifest)?;
        if bytes.len() > SYNC_MAX_CHUNK_BYTES {
            return Err(MergeErrorV1::InvalidManifest);
        }
        let hash = digest(&SHA256, &bytes);
        let mut output = [0u8; 32];
        output.copy_from_slice(hash.as_ref());
        Ok(output)
    }

    fn signing_bytes(&self, vault_id: &[u8; SYNC_ID_BYTES]) -> Result<Vec<u8>, MergeErrorV1> {
        let writer_device_id = decode_id(&self.writer_device_id)?;
        let parent_hash = decode_hash(&self.parent_hash)?;
        let head_hash = decode_hash(&self.head_hash)?;
        let mut bytes = Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + 4 + 16 + 8 + 16 + 8 + 32 + 32);
        bytes.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(vault_id);
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&writer_device_id);
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&parent_hash);
        bytes.extend_from_slice(&head_hash);
        Ok(bytes)
    }
}

fn canonical_tombstone_acknowledgements(
    mut acknowledgements: Vec<SyncTombstoneAckV1>,
) -> Result<Vec<SyncTombstoneAckV1>, MergeErrorV1> {
    for acknowledgement in &acknowledgements { acknowledgement.validate()?; }
    acknowledgements.sort();
    acknowledgements.dedup();
    Ok(acknowledgements)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SyncHeadV1 {
    pub revision: u64,
    pub head_hash: [u8; 32],
}

impl SyncHeadV1 {
    pub fn genesis() -> Self {
        Self {
            revision: 0,
            head_hash: [0; 32],
        }
    }

    pub fn new(revision: u64, head_hash: [u8; 32]) -> Self {
        Self { revision, head_hash }
    }
}

pub enum ManifestDecisionV1 {
    Duplicate,
    Advanced(SyncHeadV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeErrorV1 {
    InvalidOperation,
    InvalidManifest,
    InvalidIdentifier,
    OperationFork,
    BucketIdentityFork,
    BucketDescriptorFork,
    RevisionFork,
    Rollback,
    InvalidAncestry,
    RevisionGap,
    TombstoneNotAcknowledged,
}

impl fmt::Display for MergeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperation => "invalid sync operation",
            Self::InvalidManifest => "invalid sync manifest",
            Self::InvalidIdentifier => "invalid sync identifier",
            Self::OperationFork => "a device reused an operation counter with different content",
            Self::BucketIdentityFork => "one event identity was assigned to different sync buckets",
            Self::BucketDescriptorFork => "one sync bucket ID has conflicting metadata",
            Self::RevisionFork => "sync revision conflicts with the stored head",
            Self::Rollback => "sync manifest would roll back the stored head",
            Self::InvalidAncestry => "sync manifest parent does not match the stored head",
            Self::RevisionGap => "sync manifest revision is not the next revision",
            Self::TombstoneNotAcknowledged => "active devices have not acknowledged the tombstone",
        })
    }
}

impl std::error::Error for MergeErrorV1 {}

#[derive(PartialEq)]
pub struct MergedEventV1 {
    pub origin_device_id: String,
    pub local_event_id: u64,
    pub sync_bucket_id: String,
    pub fields: BTreeMap<String, Value>,
    pub deleted: bool,
}

pub struct MergeConflictV1 {
    pub origin_device_id: String,
    pub local_event_id: u64,
    pub field: String,
    pub winner_device_id: String,
    pub winner_counter: u64,
    pub winner_is_tombstone: bool,
}

#[derive(Serialize)]
pub struct PendingPolicyConflictV1 {
    pub devices: Vec<String>,
    pub versions: Vec<u64>,
}

pub struct MergeResultV1 {
    pub operations: Vec<SyncOperationV1>,
    pub events: Vec<MergedEventV1>,
    pub conflicts: Vec<MergeConflictV1>,
    pub pending_policy_conflict: Option<PendingPolicyConflictV1>,
}

struct FieldCandidate {
    device_id: [u8; SYNC_ID_BYTES],
    counter: u64,
    value: Value,
}

#[derive(Default)]
struct EventCandidates {
    sync_bucket_id: Option<String>,
    fields: BTreeMap<String, Vec<FieldCandidate>>,
    tombstones: Vec<([u8; SYNC_ID_BYTES], u64)>,
}

pub fn merge_operations(
    local: &[SyncOperationV1],
    remote: &[SyncOperationV1],
) -> Result<MergeResultV1, MergeErrorV1> {
    let operations = canonical_operations(local.iter().chain(remote).cloned().collect(), MAX_MERGE_HISTORY)?;
    let mut events: BTreeMap<([u8; SYNC_ID_BYTES], u64), EventCandidates> = BTreeMap::new();
    let mut bucket_descriptors = BTreeMap::<String, SyncBucketDescriptorV1>::new();
    let mut policies = Vec::new();

    for operation in &operations {
        if operation.kind == SyncOperationKindV1::PolicyChange {
            policies.push(operation);
            continue;
        }
        if let Some(descriptor) = &operation.bucket_descriptor {
            let bucket_id = operation.sync_bucket_id.as_ref().ok_or(MergeErrorV1::InvalidOperation)?;
            if bucket_descriptors.get(bucket_id).is_some_and(|existing| existing != descriptor) {
                return Err(MergeErrorV1::BucketDescriptorFork);
            }
            bucket_descriptors.insert(bucket_id.clone(), descriptor.clone());
        }
        let device_id = decode_id(&operation.device_id)?;
        let origin_device_id = decode_id(&operation.origin_device_id)?;
        let local_event_id = operation.local_event_id.ok_or(MergeErrorV1::InvalidOperation)?;
        let sync_bucket_id = operation.sync_bucket_id.as_ref().ok_or(MergeErrorV1::InvalidOperation)?;
        let event = events.entry((origin_device_id, local_event_id)).or_default();
        if event.sync_bucket_id.as_ref().is_some_and(|existing| existing != sync_bucket_id) {
            return Err(MergeErrorV1::BucketIdentityFork);
        }
        event.sync_bucket_id.get_or_insert_with(|| sync_bucket_id.clone());
        if operation.kind == SyncOperationKindV1::Tombstone {
            event.tombstones.push((device_id, operation.counter));
        } else {
            for (field, value) in &operation.fields {
                event.fields.entry(field.clone()).or_default().push(FieldCandidate {
                    device_id,
                    counter: operation.counter,
                    value: value.clone(),
                });
            }
        }
    }

    let pending_policy_conflict = policy_conflict(&policies)?;
    let mut merged_events = Vec::with_capacity(events.len());
    let mut conflicts = Vec::new();
    for ((origin_device_id, local_event_id), event) in events {
        let sync_bucket_id = event.sync_bucket_id.ok_or(MergeErrorV1::InvalidOperation)?;
        let tombstone = event.tombstones.iter().max_by(|left, right| {
            left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0))
        });
        let tombstone_counter = tombstone.map(|value| value.1);
        let resurrection = tombstone_counter.is_some_and(|counter| {
            operations.iter().any(|operation| {
                operation.kind == SyncOperationKindV1::Upsert
                    && operation.origin_device_id == URL_SAFE_NO_PAD.encode(origin_device_id)
                    && operation.local_event_id == Some(local_event_id)
                    && operation.counter > counter
            })
        });
        let deleted = tombstone.is_some() && !resurrection;
        let mut fields = BTreeMap::new();
        for (field, mut candidates) in event.fields {
            candidates.sort_by(candidate_order);
            let winner = candidates.last().ok_or(MergeErrorV1::InvalidOperation)?;
            let different_values = candidates
                .iter()
                .any(|candidate| candidate.device_id != winner.device_id && candidate.value != winner.value);
            let tombstone_wins = tombstone_counter.is_some_and(|counter| counter >= winner.counter);
            if tombstone_wins {
                if tombstone_counter == Some(winner.counter) {
                    let (tombstone_device, _) = tombstone.ok_or(MergeErrorV1::InvalidOperation)?;
                    conflicts.push(MergeConflictV1 {
                        origin_device_id: URL_SAFE_NO_PAD.encode(origin_device_id),
                        local_event_id,
                        field,
                        winner_device_id: URL_SAFE_NO_PAD.encode(*tombstone_device),
                        winner_counter: winner.counter,
                        winner_is_tombstone: true,
                    });
                }
            } else {
                if different_values {
                    conflicts.push(MergeConflictV1 {
                        origin_device_id: URL_SAFE_NO_PAD.encode(origin_device_id),
                        local_event_id,
                        field: field.clone(),
                        winner_device_id: URL_SAFE_NO_PAD.encode(winner.device_id),
                        winner_counter: winner.counter,
                        winner_is_tombstone: false,
                    });
                }
                if !deleted {
                    fields.insert(field, winner.value.clone());
                }
            }
        }
        if deleted {
            fields.clear();
        }
        merged_events.push(MergedEventV1 {
            origin_device_id: URL_SAFE_NO_PAD.encode(origin_device_id),
            local_event_id,
            sync_bucket_id,
            fields,
            deleted,
        });
    }
    conflicts.sort_by(|left, right| {
        left.origin_device_id
            .cmp(&right.origin_device_id)
            .then_with(|| left.local_event_id.cmp(&right.local_event_id))
            .then_with(|| left.field.cmp(&right.field))
    });
    Ok(MergeResultV1 {
        operations,
        events: merged_events,
        conflicts,
        pending_policy_conflict,
    })
}

pub fn tombstone_collectible(
    active_verified_devices: &[String],
    acknowledged_devices: &[String],
) -> Result<bool, MergeErrorV1> {
    let active = active_verified_devices
        .iter()
        .map(|device| decode_id(device))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let acknowledged = acknowledged_devices
        .iter()
        .map(|device| decode_id(device))
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(active.is_subset(&acknowledged))
}

pub fn pending_tombstone_ack_device_ids(
    active_verified_devices: &[[u8; SYNC_ID_BYTES]],
    acknowledged_devices: &[[u8; SYNC_ID_BYTES]],
) -> Vec<[u8; SYNC_ID_BYTES]> {
    let acknowledged: BTreeSet<_> = acknowledged_devices.iter().copied().collect();
    active_verified_devices
        .iter()
        .copied()
        .filter(|device_id| !acknowledged.contains(device_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub struct SyncTombstoneDeletionPermitV1 {
    object_id: String,
}

pub struct SyncTombstoneAckProofV1 {
    active_verified_devices: Vec<String>,
    acknowledged_devices: Vec<String>,
}

impl SyncTombstoneAckProofV1 {
    pub fn new(active_verified_devices: Vec<String>, acknowledged_devices: Vec<String>) -> Self {
        Self { active_verified_devices, acknowledged_devices }
    }
}

impl SyncTombstoneDeletionPermitV1 {
    pub fn authorize(
        object_id: &str,
        tombstone_proofs: &[SyncTombstoneAckProofV1],
    ) -> Result<Self, MergeErrorV1> {
        decode_id(object_id)?;
        if tombstone_proofs.is_empty() {
            return Err(MergeErrorV1::TombstoneNotAcknowledged);
        }
        for proof in tombstone_proofs {
            if !tombstone_collectible(&proof.active_verified_devices, &proof.acknowledged_devices)? {
                return Err(MergeErrorV1::TombstoneNotAcknowledged);
            }
        }
        Ok(Self { object_id: object_id.to_owned() })
    }

    pub(crate) fn object_id(&self) -> &str { &self.object_id }
}

fn candidate_order(left: &FieldCandidate, right: &FieldCandidate) -> Ordering {
    left.counter
        .cmp(&right.counter)
        .then_with(|| left.device_id.cmp(&right.device_id))
}

fn policy_conflict(
    operations: &[&SyncOperationV1],
) -> Result<Option<PendingPolicyConflictV1>, MergeErrorV1> {
    let Some(first) = operations.first() else {
        return Ok(None);
    };
    if operations.iter().all(|operation| {
        operation.policy_version == first.policy_version && operation.fields == first.fields
    }) {
        return Ok(None);
    }
    let mut devices = BTreeSet::new();
    let mut versions = BTreeSet::new();
    for operation in operations {
        devices.insert((decode_id(&operation.device_id)?, operation.device_id.clone()));
        versions.insert(operation.policy_version.ok_or(MergeErrorV1::InvalidOperation)?);
    }
    Ok(Some(PendingPolicyConflictV1 {
        devices: devices.into_iter().map(|(_, device)| device).collect(),
        versions: versions.into_iter().collect(),
    }))
}

fn canonical_operations(
    operations: Vec<SyncOperationV1>,
    limit: usize,
) -> Result<Vec<SyncOperationV1>, MergeErrorV1> {
    // ponytail: cap one in-memory epoch merge at recovery's 100k operation bound; use a SQL-backed projection if real vaults outgrow it.
    if operations.len() > limit {
        return Err(MergeErrorV1::InvalidManifest);
    }
    let mut canonical = BTreeMap::new();
    for operation in operations {
        operation.validate()?;
        let key = (decode_id(&operation.device_id)?, operation.counter);
        match canonical.get(&key) {
            Some(existing) if existing == &operation => continue,
            Some(_) => return Err(MergeErrorV1::OperationFork),
            None => {
                canonical.insert(key, operation);
            }
        }
    }
    Ok(canonical.into_values().collect())
}

fn decode_id(value: &str) -> Result<[u8; SYNC_ID_BYTES], MergeErrorV1> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| MergeErrorV1::InvalidIdentifier)?
        .try_into()
        .map_err(|_| MergeErrorV1::InvalidIdentifier)
}

fn decode_hash(value: &str) -> Result<[u8; 32], MergeErrorV1> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| MergeErrorV1::InvalidManifest)?
        .try_into()
        .map_err(|_| MergeErrorV1::InvalidManifest)
}
