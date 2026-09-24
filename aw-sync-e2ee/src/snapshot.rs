use aw_models::{SyncChunkHeaderV1, SyncEnvelopeV1, SYNC_ID_BYTES, SYNC_MAX_CHUNK_BYTES, SYNC_SCHEMA_VERSION_V1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::fill_random;
use crate::{decrypt_chunk, encrypt_chunk, SyncErrorV1, VaultDataKeyV1};

const SNAPSHOT_DOMAIN: &[u8] = b"PeakActivity-Sync-Snapshot-v1\0";
const SNAPSHOT_HEADER_BYTES: usize = SNAPSHOT_DOMAIN.len() + SYNC_ID_BYTES + 8;
const SNAPSHOT_CHUNK_BYTES: usize = SYNC_MAX_CHUNK_BYTES - SNAPSHOT_HEADER_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotChunkMetadataV1 {
    pub snapshot_id: String,
    pub index: u32,
    pub count: u32,
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
            envelope.validate().map_err(|_| SyncErrorV1::InvalidEnvelope)?;
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
    let count = u32::try_from(snapshot.envelopes.len()).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let mut output = Zeroizing::new(Vec::new());
    for (expected_index, envelope) in snapshot.envelopes.iter().enumerate() {
        let plaintext = decrypt_chunk(key, envelope)?;
        if plaintext.len() < SNAPSHOT_HEADER_BYTES
            || &plaintext[..SNAPSHOT_DOMAIN.len()] != SNAPSHOT_DOMAIN
            || plaintext[SNAPSHOT_DOMAIN.len()..SNAPSHOT_DOMAIN.len() + SYNC_ID_BYTES] != snapshot_id
        {
            return Err(SyncErrorV1::InvalidEnvelope);
        }
        let index_start = SNAPSHOT_DOMAIN.len() + SYNC_ID_BYTES;
        let index = u32::from_be_bytes(plaintext[index_start..index_start + 4].try_into().unwrap());
        let found_count = u32::from_be_bytes(plaintext[index_start + 4..SNAPSHOT_HEADER_BYTES].try_into().unwrap());
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
    let count = u32::from_be_bytes(plaintext[index_start + 4..SNAPSHOT_HEADER_BYTES].try_into().unwrap());
    if count == 0 || index >= count {
        return Err(SyncErrorV1::InvalidEnvelope);
    }
    Ok(SnapshotChunkMetadataV1 { snapshot_id, index, count })
}

fn decode_id(value: &str) -> Result<[u8; SYNC_ID_BYTES], SyncErrorV1> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| SyncErrorV1::InvalidEnvelope)?
        .try_into().map_err(|_| SyncErrorV1::InvalidEnvelope)
}
