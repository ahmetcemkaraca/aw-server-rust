use aw_models::{
    SyncChunkHeaderV1, SyncEnvelopeV1, SYNC_ID_BYTES, SYNC_MAX_CHUNK_BYTES, SYNC_SCHEMA_VERSION_V1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::{decrypt_chunk, encrypt_chunk, SyncErrorV1, VaultDataKeyV1};

const SNAPSHOT_DOMAIN: &[u8] = b"PeakActivity-Sync-Snapshot-v1\0";
const SNAPSHOT_HEADER_BYTES: usize = SNAPSHOT_DOMAIN.len() + SYNC_ID_BYTES + 8;
const SNAPSHOT_CHUNK_BYTES: usize = SYNC_MAX_CHUNK_BYTES - SNAPSHOT_HEADER_BYTES;
pub const MAX_BACKUP_SCAN_OBJECTS: usize = 100_000;
pub const MAX_BACKUP_SCAN_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_BACKUP_BUNDLE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotChunkMetadataV1 {
    pub snapshot_id: String,
    pub index: u32,
    pub count: u32,
}

#[derive(Debug)]
pub struct SnapshotObjectGroupV1 {
    pub snapshot_id: String,
    pub declared_object_count: u32,
    pub object_ids: Vec<String>,
    pub complete: bool,
    pub bundle_sha256: Option<String>,
}

#[derive(Debug, Default)]
pub struct SnapshotObjectIndexV1 {
    pub groups: Vec<SnapshotObjectGroupV1>,
    pub unavailable_epochs: BTreeMap<u64, usize>,
    pub invalid_objects: Vec<String>,
    pub operation_objects: usize,
}

pub struct SnapshotIndexBuilderV1<'a> {
    key: &'a VaultDataKeyV1,
    seen: BTreeMap<String, [u8; 32]>,
    groups: BTreeMap<String, IndexedSnapshot>,
    index: SnapshotObjectIndexV1,
    bytes: usize,
    object_limit: usize,
    byte_limit: usize,
    error: Option<SyncErrorV1>,
}

struct IndexedSnapshot {
    count: u32,
    consistent: bool,
    objects: BTreeMap<u32, (String, [u8; 32])>,
}

impl<'a> SnapshotIndexBuilderV1<'a> {
    pub fn new(key: &'a VaultDataKeyV1) -> Self {
        Self::bounded(key, MAX_BACKUP_SCAN_OBJECTS, MAX_BACKUP_SCAN_BYTES)
    }

    fn bounded(key: &'a VaultDataKeyV1, object_limit: usize, byte_limit: usize) -> Self {
        Self {
            key,
            seen: BTreeMap::new(),
            groups: BTreeMap::new(),
            index: SnapshotObjectIndexV1::default(),
            bytes: 0,
            object_limit,
            byte_limit,
            error: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_limits(key: &'a VaultDataKeyV1, objects: usize, bytes: usize) -> Self {
        Self::bounded(key, objects, bytes)
    }

    /// Records only authenticated headers and immutable object digests, never activity.
    pub fn push(&mut self, envelope: &SyncEnvelopeV1) -> Result<(), SyncErrorV1> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let result = self.admit(envelope);
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }

    fn admit(&mut self, envelope: &SyncEnvelopeV1) -> Result<(), SyncErrorV1> {
        envelope
            .validate()
            .map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        if decode_id(&envelope.vault_id)? != self.key.vault_id() {
            return Err(SyncErrorV1::InvalidKeyScope);
        }
        let encoded = serde_json::to_vec(envelope).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &encoded)
            .as_ref()
            .try_into()
            .unwrap();
        if let Some(existing) = self.seen.get(&envelope.object_id) {
            return if *existing == digest {
                Ok(())
            } else {
                Err(SyncErrorV1::InvalidEnvelope)
            };
        }
        let next_bytes = self
            .bytes
            .checked_add(encoded.len())
            .ok_or(SyncErrorV1::PayloadTooLarge)?;
        if self.seen.len() >= self.object_limit || next_bytes > self.byte_limit {
            return Err(SyncErrorV1::PayloadTooLarge);
        }
        self.bytes = next_bytes;
        self.seen.insert(envelope.object_id.clone(), digest);
        if envelope.key_epoch != self.key.key_epoch() {
            *self
                .index
                .unavailable_epochs
                .entry(envelope.key_epoch)
                .or_default() += 1;
            return Ok(());
        }
        match inspect_snapshot_chunk(self.key, envelope) {
            Ok(chunk) => {
                let group =
                    self.groups
                        .entry(chunk.snapshot_id)
                        .or_insert_with(|| IndexedSnapshot {
                            count: chunk.count,
                            consistent: true,
                            objects: BTreeMap::new(),
                        });
                if group.count != chunk.count || group.objects.contains_key(&chunk.index) {
                    group.consistent = false;
                } else {
                    group
                        .objects
                        .insert(chunk.index, (envelope.object_id.clone(), digest));
                }
            }
            Err(_) if crate::decrypt_manifest(self.key, envelope).is_ok() => {
                self.index.operation_objects += 1;
            }
            Err(_) => self.index.invalid_objects.push(envelope.object_id.clone()),
        }
        Ok(())
    }

    /// Completeness here covers headers only; callers must verify the full recovery payload.
    pub fn finish(mut self) -> Result<SnapshotObjectIndexV1, SyncErrorV1> {
        if let Some(error) = self.error {
            return Err(error);
        }
        for (snapshot_id, group) in self.groups {
            let complete = group.consistent && group.objects.len() as u64 == u64::from(group.count);
            let bundle_sha256 = if complete {
                let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
                hash.update(b"PeakActivity-Backup-Bundle-v1\0");
                hash.update(&self.key.vault_id());
                hash.update(&self.key.key_epoch().to_be_bytes());
                hash.update(&decode_id(&snapshot_id)?);
                hash.update(&group.count.to_be_bytes());
                for (object_id, digest) in group.objects.values() {
                    hash.update(&decode_id(object_id)?);
                    hash.update(digest);
                }
                Some(
                    hash.finish()
                        .as_ref()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                )
            } else {
                None
            };
            self.index.groups.push(SnapshotObjectGroupV1 {
                snapshot_id,
                declared_object_count: group.count,
                object_ids: group.objects.into_values().map(|(id, _)| id).collect(),
                complete,
                bundle_sha256,
            });
        }
        self.index.invalid_objects.sort();
        Ok(self.index)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSyncSnapshotV1 {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub envelopes: Vec<SyncEnvelopeV1>,
}

impl EncryptedSyncSnapshotV1 {
    pub fn validate(&self) -> Result<(), SyncErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 || self.envelopes.is_empty() {
            return Err(SyncErrorV1::InvalidEnvelope);
        }
        let snapshot_id = decode_id(&self.snapshot_id)?;
        let first = &self.envelopes[0];
        first.validate().map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        let mut object_ids = std::collections::BTreeSet::new();
        for envelope in &self.envelopes {
            envelope
                .validate()
                .map_err(|_| SyncErrorV1::InvalidEnvelope)?;
            if envelope.vault_id != first.vault_id
                || envelope.key_epoch != first.key_epoch
                || !object_ids.insert(envelope.object_id.clone())
            {
                return Err(SyncErrorV1::InvalidEnvelope);
            }
        }
        let _ = snapshot_id;
        Ok(())
    }
}

pub fn encrypt_snapshot(
    key: &VaultDataKeyV1,
    plaintext: &[u8],
) -> Result<EncryptedSyncSnapshotV1, SyncErrorV1> {
    let mut snapshot_id = [0u8; SYNC_ID_BYTES];
    fill_random(&mut snapshot_id)?;
    let snapshot_id_text = URL_SAFE_NO_PAD.encode(snapshot_id);
    let count = plaintext.len().max(1).div_ceil(SNAPSHOT_CHUNK_BYTES);
    let count = u32::try_from(count).map_err(|_| SyncErrorV1::PayloadTooLarge)?;
    let vault_id = URL_SAFE_NO_PAD.encode(key.vault_id());
    let mut envelopes = Vec::with_capacity(count as usize);
    for index in 0..count {
        let start = index as usize * SNAPSHOT_CHUNK_BYTES;
        let end = (start + SNAPSHOT_CHUNK_BYTES).min(plaintext.len());
        let chunk = plaintext.get(start..end).unwrap_or_default();
        let mut payload = Zeroizing::new(Vec::with_capacity(SNAPSHOT_HEADER_BYTES + chunk.len()));
        payload.extend_from_slice(SNAPSHOT_DOMAIN);
        payload.extend_from_slice(&snapshot_id);
        payload.extend_from_slice(&index.to_be_bytes());
        payload.extend_from_slice(&count.to_be_bytes());
        payload.extend_from_slice(chunk);
        let mut object_id = [0u8; SYNC_ID_BYTES];
        fill_random(&mut object_id)?;
        let header = SyncChunkHeaderV1 {
            schema_version: SYNC_SCHEMA_VERSION_V1,
            object_id: URL_SAFE_NO_PAD.encode(object_id),
            vault_id: vault_id.clone(),
            key_epoch: key.key_epoch(),
        };
        envelopes.push(encrypt_chunk(key, &header, &payload)?);
    }
    let snapshot = EncryptedSyncSnapshotV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        snapshot_id: snapshot_id_text,
        envelopes,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

pub fn decrypt_snapshot(
    key: &VaultDataKeyV1,
    snapshot: &EncryptedSyncSnapshotV1,
) -> Result<Zeroizing<Vec<u8>>, SyncErrorV1> {
    snapshot.validate()?;
    let snapshot_id = decode_id(&snapshot.snapshot_id)?;
    let count =
        u32::try_from(snapshot.envelopes.len()).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let mut output = Zeroizing::new(Vec::new());
    for (expected_index, envelope) in snapshot.envelopes.iter().enumerate() {
        let plaintext = decrypt_chunk(key, envelope)?;
        if plaintext.len() < SNAPSHOT_HEADER_BYTES
            || &plaintext[..SNAPSHOT_DOMAIN.len()] != SNAPSHOT_DOMAIN
            || plaintext[SNAPSHOT_DOMAIN.len()..SNAPSHOT_DOMAIN.len() + SYNC_ID_BYTES]
                != snapshot_id
        {
            return Err(SyncErrorV1::InvalidEnvelope);
        }
        let index_start = SNAPSHOT_DOMAIN.len() + SYNC_ID_BYTES;
        let index = u32::from_be_bytes(plaintext[index_start..index_start + 4].try_into().unwrap());
        let found_count = u32::from_be_bytes(
            plaintext[index_start + 4..SNAPSHOT_HEADER_BYTES]
                .try_into()
                .unwrap(),
        );
        if index as usize != expected_index || found_count != count {
            return Err(SyncErrorV1::InvalidEnvelope);
        }
        output.extend_from_slice(&plaintext[SNAPSHOT_HEADER_BYTES..]);
    }
    Ok(output)
}

/// Checks a single authenticated snapshot chunk without exposing its activity bytes.
pub fn inspect_snapshot_chunk(
    key: &VaultDataKeyV1,
    envelope: &SyncEnvelopeV1,
) -> Result<SnapshotChunkMetadataV1, SyncErrorV1> {
    let plaintext = decrypt_chunk(key, envelope)?;
    if plaintext.len() < SNAPSHOT_HEADER_BYTES
        || &plaintext[..SNAPSHOT_DOMAIN.len()] != SNAPSHOT_DOMAIN
    {
        return Err(SyncErrorV1::InvalidEnvelope);
    }
    let id_start = SNAPSHOT_DOMAIN.len();
    let snapshot_id = URL_SAFE_NO_PAD.encode(&plaintext[id_start..id_start + SYNC_ID_BYTES]);
    let index_start = id_start + SYNC_ID_BYTES;
    let index = u32::from_be_bytes(plaintext[index_start..index_start + 4].try_into().unwrap());
    let count = u32::from_be_bytes(
        plaintext[index_start + 4..SNAPSHOT_HEADER_BYTES]
            .try_into()
            .unwrap(),
    );
    if count == 0 || index >= count {
        return Err(SyncErrorV1::InvalidEnvelope);
    }
    Ok(SnapshotChunkMetadataV1 {
        snapshot_id,
        index,
        count,
    })
}

fn decode_id(value: &str) -> Result<[u8; SYNC_ID_BYTES], SyncErrorV1> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SyncErrorV1::InvalidEnvelope)?
        .try_into()
        .map_err(|_| SyncErrorV1::InvalidEnvelope)
}
