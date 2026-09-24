use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SYNC_SCHEMA_VERSION_V1: u32 = 1;
pub const SYNC_EGRESS_PURPOSE_V1: &str = "sync-object-v1";
pub const SYNC_KEY_BYTES: usize = 32;
pub const SYNC_ID_BYTES: usize = 16;
pub const SYNC_NONCE_BYTES: usize = 24;
pub const SYNC_CHALLENGE_BYTES: usize = 32;
pub const SYNC_TAG_BYTES: usize = 16;
pub const SYNC_MAX_CHUNK_BYTES: usize = 1024 * 1024;
pub const SYNC_MAX_KEY_TRANSFER_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncChunkHeaderV1 {
    pub schema_version: u32,
    pub object_id: String,
    pub vault_id: String,
    pub key_epoch: u64,
}

impl SyncChunkHeaderV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        validate_base64_length(&self.object_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.vault_id, SYNC_ID_BYTES)?;
        if self.key_epoch == 0 {
            return Err(SyncWireErrorV1::InvalidKeyEpoch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncEnvelopeV1 {
    pub schema_version: u32,
    pub object_id: String,
    pub vault_id: String,
    pub key_epoch: u64,
    pub nonce: String,
    pub ciphertext: String,
}

impl SyncEnvelopeV1 {
    pub fn header(&self) -> SyncChunkHeaderV1 {
        SyncChunkHeaderV1 {
            schema_version: self.schema_version,
            object_id: self.object_id.clone(),
            vault_id: self.vault_id.clone(),
            key_epoch: self.key_epoch,
        }
    }

    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        self.header().validate()?;
        validate_base64_length(&self.nonce, SYNC_NONCE_BYTES)?;
        let ciphertext = decode_base64(&self.ciphertext)?;
        if ciphertext.len() < SYNC_TAG_BYTES || ciphertext.len() > SYNC_MAX_CHUNK_BYTES + SYNC_TAG_BYTES {
            return Err(SyncWireErrorV1::InvalidCiphertextLength);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncRelayOperationV1 {
    PutIfAbsent,
    Get,
    ListOpaqueHeads,
    DeleteAfterTombstone,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRelayRequestV1 {
    pub schema_version: u32,
    pub operation: SyncRelayOperationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<SyncEnvelopeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
}

impl SyncRelayRequestV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        match self.operation {
            SyncRelayOperationV1::PutIfAbsent => {
                let object_id = self.object_id.as_deref().ok_or(SyncWireErrorV1::InvalidSyncRequest)?;
                let vault_id = self.vault_id.as_deref().ok_or(SyncWireErrorV1::InvalidSyncRequest)?;
                validate_base64_length(object_id, SYNC_ID_BYTES)?;
                validate_base64_length(vault_id, SYNC_ID_BYTES)?;
                let envelope = self.envelope.as_ref().ok_or(SyncWireErrorV1::InvalidSyncRequest)?;
                envelope.validate()?;
                if envelope.object_id != object_id || envelope.vault_id != vault_id
                    || self.cursor.is_some() || self.limit.is_some()
                {
                    return Err(SyncWireErrorV1::InvalidSyncRequest);
                }
            }
            SyncRelayOperationV1::Get | SyncRelayOperationV1::DeleteAfterTombstone => {
                validate_base64_length(
                    self.object_id.as_deref().ok_or(SyncWireErrorV1::InvalidSyncRequest)?,
                    SYNC_ID_BYTES,
                )?;
                if self.vault_id.is_some() || self.envelope.is_some()
                    || self.cursor.is_some() || self.limit.is_some()
                {
                    return Err(SyncWireErrorV1::InvalidSyncRequest);
                }
            }
            SyncRelayOperationV1::ListOpaqueHeads => {
                validate_base64_length(
                    self.vault_id.as_deref().ok_or(SyncWireErrorV1::InvalidSyncRequest)?,
                    SYNC_ID_BYTES,
                )?;
                if self.object_id.is_some() || self.envelope.is_some()
                    || self.limit.filter(|limit| (1..=64).contains(limit)).is_none()
                {
                    return Err(SyncWireErrorV1::InvalidSyncRequest);
                }
                if let Some(cursor) = &self.cursor { validate_base64_length(cursor, SYNC_ID_BYTES)?; }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRelayResponseV1 {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inserted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<SyncEnvelopeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub objects: Vec<SyncEnvelopeV1>,
}

impl SyncRelayResponseV1 {
    pub fn validate_for(&self, request: &SyncRelayRequestV1) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 { return Err(SyncWireErrorV1::UnknownVersion); }
        let valid = match request.operation {
            SyncRelayOperationV1::PutIfAbsent => self.inserted.is_some() && self.deleted.is_none()
                && self.envelope.is_none() && self.next_cursor.is_none() && self.objects.is_empty(),
            SyncRelayOperationV1::Get => self.inserted.is_none() && self.deleted.is_none()
                && self.next_cursor.is_none() && self.objects.is_empty(),
            SyncRelayOperationV1::ListOpaqueHeads => self.inserted.is_none() && self.deleted.is_none()
                && self.envelope.is_none() && self.objects.len() <= request.limit.unwrap_or(0) as usize,
            SyncRelayOperationV1::DeleteAfterTombstone => self.deleted.is_some() && self.inserted.is_none()
                && self.envelope.is_none() && self.next_cursor.is_none() && self.objects.is_empty(),
        };
        if !valid { return Err(SyncWireErrorV1::InvalidSyncRequest); }
        if let Some(envelope) = &self.envelope {
            envelope.validate()?;
            if request.object_id.as_deref().is_some_and(|id| id != envelope.object_id) {
                return Err(SyncWireErrorV1::InvalidSyncRequest);
            }
        }
        for envelope in &self.objects {
            envelope.validate()?;
            if Some(envelope.vault_id.as_str()) != request.vault_id.as_deref() {
                return Err(SyncWireErrorV1::InvalidSyncRequest);
            }
        }
        if request.operation == SyncRelayOperationV1::ListOpaqueHeads {
            if self.objects.windows(2).any(|pair| pair[0].object_id >= pair[1].object_id)
                || request.cursor.as_ref().zip(self.objects.first()).is_some_and(|(cursor, first)| first.object_id.as_str() <= cursor.as_str())
            {
                return Err(SyncWireErrorV1::InvalidSyncRequest);
            }
            if let Some(cursor) = &self.next_cursor {
                validate_base64_length(cursor, SYNC_ID_BYTES)?;
                if self.objects.last().is_none_or(|last| last.object_id.as_str() != cursor.as_str())
                    || self.objects.len() != request.limit.unwrap_or(0) as usize
                {
                    return Err(SyncWireErrorV1::InvalidSyncRequest);
                }
            }
        } else if let Some(cursor) = &self.next_cursor {
            validate_base64_length(cursor, SYNC_ID_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePublicIdentityV1 {
    pub schema_version: u32,
    pub device_id: String,
    pub x25519_public_key: String,
    pub ed25519_public_key: String,
}

impl DevicePublicIdentityV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        validate_base64_length(&self.device_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.x25519_public_key, SYNC_KEY_BYTES)?;
        validate_base64_length(&self.ed25519_public_key, SYNC_KEY_BYTES)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncBucketDescriptorV1 {
    pub bucket_type: String,
    pub client: String,
    pub data: BTreeMap<String, Value>,
}

impl SyncBucketDescriptorV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.bucket_type.len() > 128
            || self.client.len() > 128
            || self.bucket_type.chars().any(char::is_control)
            || self.client.chars().any(char::is_control)
            || serde_json::to_vec(self)
                .map_err(|_| SyncWireErrorV1::InvalidSyncRequest)?
                .len()
                > SYNC_MAX_CHUNK_BYTES
        {
            return Err(SyncWireErrorV1::InvalidSyncRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingInvitationV1 {
    pub schema_version: u32,
    pub offer_id: String,
    pub issuer: DevicePublicIdentityV1,
    pub recipient_device_id: String,
    pub issuer_ephemeral_key: String,
    pub challenge: String,
}

impl PairingInvitationV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        self.issuer.validate()?;
        validate_base64_length(&self.offer_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.recipient_device_id, SYNC_ID_BYTES)?;
        if decode_base64(&self.issuer.device_id)? == decode_base64(&self.recipient_device_id)? {
            return Err(SyncWireErrorV1::InvalidPairing);
        }
        validate_base64_length(&self.issuer_ephemeral_key, SYNC_KEY_BYTES)?;
        validate_pairing_challenge(&self.challenge)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingResponseV1 {
    pub schema_version: u32,
    pub offer_id: String,
    pub recipient: DevicePublicIdentityV1,
    pub recipient_ephemeral_key: String,
}

impl PairingResponseV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        self.recipient.validate()?;
        validate_base64_length(&self.offer_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.recipient_ephemeral_key, SYNC_KEY_BYTES)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingOfferV1 {
    pub schema_version: u32,
    pub offer_id: String,
    pub issuer: DevicePublicIdentityV1,
    pub recipient: DevicePublicIdentityV1,
    pub issuer_ephemeral_key: String,
    pub recipient_ephemeral_key: String,
    pub challenge: String,
}

impl PairingOfferV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        self.issuer.validate()?;
        self.recipient.validate()?;
        if decode_base64(&self.issuer.device_id)? == decode_base64(&self.recipient.device_id)? {
            return Err(SyncWireErrorV1::InvalidPairing);
        }
        validate_base64_length(&self.offer_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.issuer_ephemeral_key, SYNC_KEY_BYTES)?;
        validate_base64_length(&self.recipient_ephemeral_key, SYNC_KEY_BYTES)?;
        validate_pairing_challenge(&self.challenge)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingConfirmationV1 {
    pub schema_version: u32,
    pub offer_id: String,
    pub device_id: String,
    pub transcript_hash: String,
    pub authenticator: String,
}

impl PairingConfirmationV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        validate_base64_length(&self.offer_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.device_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.transcript_hash, SYNC_KEY_BYTES)?;
        validate_base64_length(&self.authenticator, SYNC_KEY_BYTES)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedKeyTransferV1 {
    pub schema_version: u32,
    pub offer_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl EncryptedKeyTransferV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        validate_base64_length(&self.offer_id, SYNC_ID_BYTES)?;
        validate_base64_length(&self.nonce, SYNC_NONCE_BYTES)?;
        let ciphertext = decode_base64(&self.ciphertext)?;
        if ciphertext.len() < SYNC_KEY_BYTES + SYNC_TAG_BYTES
            || ciphertext.len() > SYNC_MAX_KEY_TRANSFER_BYTES + SYNC_TAG_BYTES
        {
            return Err(SyncWireErrorV1::InvalidCiphertextLength);
        }
        Ok(())
    }
}

fn validate_pairing_challenge(challenge: &str) -> Result<(), SyncWireErrorV1> {
    let challenge = decode_base64(challenge)?;
    if challenge.len() != SYNC_CHALLENGE_BYTES {
        return Err(SyncWireErrorV1::InvalidChallengeLength);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKitV1 {
    pub schema_version: u32,
    pub kdf: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl RecoveryKitV1 {
    pub fn validate(&self) -> Result<(), SyncWireErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 {
            return Err(SyncWireErrorV1::UnknownVersion);
        }
        if self.kdf != "argon2id-v19"
            || self.memory_kib != 65_536
            || self.iterations != 3
            || self.parallelism != 4
        {
            return Err(SyncWireErrorV1::UnsupportedKdf);
        }
        validate_base64_length(&self.salt, 16)?;
        validate_base64_length(&self.nonce, SYNC_NONCE_BYTES)?;
        let ciphertext = decode_base64(&self.ciphertext)?;
        if ciphertext.len() < SYNC_KEY_BYTES + SYNC_TAG_BYTES || ciphertext.len() > 4096 {
            return Err(SyncWireErrorV1::InvalidCiphertextLength);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOperationKindV1 {
    Upsert,
    Correction,
    Tombstone,
    PolicyChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncWireErrorV1 {
    UnknownVersion,
    InvalidBase64,
    InvalidIdentifierLength,
    InvalidNonceLength,
    InvalidChallengeLength,
    InvalidPairing,
    InvalidCiphertextLength,
    InvalidKeyEpoch,
    UnsupportedKdf,
    InvalidSyncRequest,
}

fn decode_base64(value: &str) -> Result<Vec<u8>, SyncWireErrorV1> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SyncWireErrorV1::InvalidBase64)
}

fn validate_base64_length(value: &str, expected: usize) -> Result<(), SyncWireErrorV1> {
    let decoded = decode_base64(value)?;
    if decoded.len() != expected {
        return Err(if expected == SYNC_NONCE_BYTES {
            SyncWireErrorV1::InvalidNonceLength
        } else {
            SyncWireErrorV1::InvalidIdentifierLength
        });
    }
    Ok(())
}
