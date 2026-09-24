use std::fmt;

use aw_models::{
    SyncChunkHeaderV1, SyncEnvelopeV1, SYNC_ID_BYTES, SYNC_KEY_BYTES, SYNC_MAX_CHUNK_BYTES,
    SYNC_NONCE_BYTES, SYNC_SCHEMA_VERSION_V1, SYNC_TAG_BYTES,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const CHUNK_AAD_DOMAIN: &[u8] = b"PeakActivity-Sync-v1\0";
const KEY_WRAP_SALT: &[u8] = b"PeakActivity-Sync-v1/KeyHierarchy";
const KEY_WRAP_INFO: &[u8] = b"PeakActivity/Sync/KeyWrap/v1";
const KEY_WRAP_AAD_DOMAIN: &[u8] = b"PeakActivity-Sync-KeyWrap-v1\0";
const KEY_BUNDLE_VERSION: u32 = 1;
const KEY_BUNDLE_BYTES: usize = 4 + SYNC_KEY_BYTES + SYNC_ID_BYTES + 8 + SYNC_NONCE_BYTES + 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncErrorV1 {
    InvalidHeader,
    InvalidEnvelope,
    InvalidKey,
    InvalidKeyScope,
    PayloadTooLarge,
    AuthenticationFailed,
    RandomnessUnavailable,
    KeyDerivationFailed,
    CipherFailure,
    InvalidPairing,
    PairingRejected,
    PairingNotConfirmed,
    PeerNotConfirmed,
    InvalidManifest,
    InvalidSignature,
    InvalidRecoveryPhrase,
    RecoveryKdfFailed,
}

impl fmt::Display for SyncErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHeader => "invalid sync header",
            Self::InvalidEnvelope => "invalid encrypted sync envelope",
            Self::InvalidKey => "invalid sync key",
            Self::InvalidKeyScope => "sync key does not match the requested vault epoch",
            Self::PayloadTooLarge => "sync chunk exceeds the maximum size",
            Self::AuthenticationFailed => "sync envelope authentication failed",
            Self::RandomnessUnavailable => "secure random source unavailable",
            Self::KeyDerivationFailed => "sync key derivation failed",
            Self::CipherFailure => "sync encryption operation failed",
            Self::InvalidPairing => "invalid device pairing exchange",
            Self::PairingRejected => "device pairing confirmation was rejected",
            Self::PairingNotConfirmed => "confirm the same pairing code on both devices",
            Self::PeerNotConfirmed => "the other device has not confirmed this pairing",
            Self::InvalidManifest => "invalid encrypted sync manifest",
            Self::InvalidSignature => "sync manifest signature is invalid",
            Self::InvalidRecoveryPhrase => "invalid recovery phrase",
            Self::RecoveryKdfFailed => "recovery key derivation failed",
        })
    }
}

impl std::error::Error for SyncErrorV1 {}

pub struct AccountRootKeyV1 {
    secret: Zeroizing<[u8; SYNC_KEY_BYTES]>,
}

impl AccountRootKeyV1 {
    pub fn from_bytes(secret: Zeroizing<[u8; SYNC_KEY_BYTES]>) -> Self {
        Self { secret }
    }

    pub(crate) fn as_bytes(&self) -> &[u8; SYNC_KEY_BYTES] {
        &self.secret
    }

    pub fn secret_for_storage(&self) -> Zeroizing<[u8; SYNC_KEY_BYTES]> {
        Zeroizing::new(*self.secret)
    }
}

pub struct VaultDataKeyV1 {
    secret: Zeroizing<[u8; SYNC_KEY_BYTES]>,
    vault_id: [u8; SYNC_ID_BYTES],
    key_epoch: u64,
}

impl VaultDataKeyV1 {
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub fn vault_id(&self) -> [u8; SYNC_ID_BYTES] {
        self.vault_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedVaultDataKeyV1 {
    pub schema_version: u32,
    pub vault_id: String,
    pub key_epoch: u64,
    pub nonce: String,
    pub ciphertext: String,
}

pub struct SyncKeyMaterialBundleV1 {
    pub account_root_key: AccountRootKeyV1,
    pub wrapped_vault_key: WrappedVaultDataKeyV1,
}

pub(super) fn encode_key_material_bundle(
    root_key: &AccountRootKeyV1,
    wrapped_vault_key: &WrappedVaultDataKeyV1,
) -> Result<Zeroizing<Vec<u8>>, SyncErrorV1> {
    wrapped_vault_key.validate()?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(KEY_BUNDLE_BYTES));
    plaintext.extend_from_slice(&KEY_BUNDLE_VERSION.to_be_bytes());
    plaintext.extend_from_slice(root_key.as_bytes());
    plaintext.extend_from_slice(
        &decode_fixed::<SYNC_ID_BYTES>(&wrapped_vault_key.vault_id)
            .map_err(|_| SyncErrorV1::InvalidEnvelope)?,
    );
    plaintext.extend_from_slice(&wrapped_vault_key.key_epoch.to_be_bytes());
    plaintext.extend_from_slice(
        &decode_fixed::<SYNC_NONCE_BYTES>(&wrapped_vault_key.nonce)
            .map_err(|_| SyncErrorV1::InvalidEnvelope)?,
    );
    plaintext.extend_from_slice(
        &decode_fixed::<48>(&wrapped_vault_key.ciphertext)
            .map_err(|_| SyncErrorV1::InvalidEnvelope)?,
    );
    Ok(plaintext)
}

pub(super) fn decode_key_material_bundle(
    plaintext: &[u8],
) -> Result<SyncKeyMaterialBundleV1, SyncErrorV1> {
    if plaintext.len() != KEY_BUNDLE_BYTES
        || u32::from_be_bytes(plaintext[..4].try_into().unwrap()) != KEY_BUNDLE_VERSION
    {
        return Err(SyncErrorV1::InvalidEnvelope);
    }
    let mut root_secret = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    root_secret.copy_from_slice(&plaintext[4..36]);
    let account_root_key = AccountRootKeyV1::from_bytes(root_secret);
    let wrapped_vault_key = WrappedVaultDataKeyV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        vault_id: URL_SAFE_NO_PAD.encode(&plaintext[36..52]),
        key_epoch: u64::from_be_bytes(plaintext[52..60].try_into().unwrap()),
        nonce: URL_SAFE_NO_PAD.encode(&plaintext[60..84]),
        ciphertext: URL_SAFE_NO_PAD.encode(&plaintext[84..132]),
    };
    wrapped_vault_key.validate()?;
    crate::unwrap_vault_data_key(&account_root_key, &wrapped_vault_key)?;
    Ok(SyncKeyMaterialBundleV1 {
        account_root_key,
        wrapped_vault_key,
    })
}

impl WrappedVaultDataKeyV1 {
    pub fn validate(&self) -> Result<(), SyncErrorV1> {
        if self.schema_version != SYNC_SCHEMA_VERSION_V1 || self.key_epoch == 0 {
            return Err(SyncErrorV1::InvalidEnvelope);
        }
        decode_fixed::<SYNC_ID_BYTES>(&self.vault_id).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        decode_fixed::<SYNC_NONCE_BYTES>(&self.nonce).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        let ciphertext =
            decode_encoded(&self.ciphertext).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
        if ciphertext.len() != SYNC_KEY_BYTES + SYNC_TAG_BYTES {
            return Err(SyncErrorV1::InvalidEnvelope);
        }
        Ok(())
    }
}

pub fn generate_account_root_key() -> Result<AccountRootKeyV1, SyncErrorV1> {
    let mut secret = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    fill_random(&mut secret[..])?;
    Ok(AccountRootKeyV1 { secret })
}

pub fn create_vault_data_key(
    root_key: &AccountRootKeyV1,
    vault_id: &str,
    key_epoch: u64,
) -> Result<(VaultDataKeyV1, WrappedVaultDataKeyV1), SyncErrorV1> {
    let vault_id_bytes =
        decode_fixed::<SYNC_ID_BYTES>(vault_id).map_err(|_| SyncErrorV1::InvalidHeader)?;
    if key_epoch == 0 {
        return Err(SyncErrorV1::InvalidHeader);
    }

    let mut secret = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    fill_random(&mut secret[..])?;
    let mut nonce = [0u8; SYNC_NONCE_BYTES];
    fill_random(&mut nonce)?;

    let wrapping_key = derive_wrapping_key(root_key, &vault_id_bytes, key_epoch)?;
    let aad = key_wrap_aad(&vault_id_bytes, key_epoch);
    let ciphertext = seal_with_nonce(&wrapping_key, &nonce, &aad, &secret[..])?;
    let wrapped = WrappedVaultDataKeyV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        vault_id: vault_id.to_owned(),
        key_epoch,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    wrapped.validate()?;

    Ok((
        VaultDataKeyV1 {
            secret,
            vault_id: vault_id_bytes,
            key_epoch,
        },
        wrapped,
    ))
}

pub fn unwrap_vault_data_key(
    root_key: &AccountRootKeyV1,
    wrapped: &WrappedVaultDataKeyV1,
) -> Result<VaultDataKeyV1, SyncErrorV1> {
    wrapped.validate()?;
    let vault_id = decode_fixed::<SYNC_ID_BYTES>(&wrapped.vault_id)
        .map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let nonce = decode_fixed::<SYNC_NONCE_BYTES>(&wrapped.nonce)
        .map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let ciphertext =
        decode_encoded(&wrapped.ciphertext).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let wrapping_key = derive_wrapping_key(root_key, &vault_id, wrapped.key_epoch)?;
    let aad = key_wrap_aad(&vault_id, wrapped.key_epoch);
    let plaintext = open_with_nonce(&wrapping_key, &nonce, &aad, ciphertext)?;
    if plaintext.len() != SYNC_KEY_BYTES {
        return Err(SyncErrorV1::InvalidEnvelope);
    }
    let mut secret = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    secret.copy_from_slice(&plaintext);
    Ok(VaultDataKeyV1 {
        secret,
        vault_id,
        key_epoch: wrapped.key_epoch,
    })
}

pub fn rotate_account_and_vault_key(
    current_root: &AccountRootKeyV1,
    current_wrapped: &WrappedVaultDataKeyV1,
) -> Result<(AccountRootKeyV1, VaultDataKeyV1, WrappedVaultDataKeyV1), SyncErrorV1> {
    unwrap_vault_data_key(current_root, current_wrapped)?;
    let next_epoch = current_wrapped
        .key_epoch
        .checked_add(1)
        .filter(|epoch| *epoch <= i64::MAX as u64)
        .ok_or(SyncErrorV1::InvalidHeader)?;
    let next_root = generate_account_root_key()?;
    let (next_key, next_wrapped) =
        create_vault_data_key(&next_root, &current_wrapped.vault_id, next_epoch)?;
    Ok((next_root, next_key, next_wrapped))
}

pub fn reencrypt_snapshot_chunks(
    old_key: &VaultDataKeyV1,
    new_key: &VaultDataKeyV1,
    envelopes: &[SyncEnvelopeV1],
) -> Result<Vec<SyncEnvelopeV1>, SyncErrorV1> {
    if old_key.vault_id != new_key.vault_id || old_key.key_epoch >= new_key.key_epoch {
        return Err(SyncErrorV1::InvalidKeyScope);
    }
    envelopes
        .iter()
        .map(|envelope| {
            let plaintext = decrypt_chunk(old_key, envelope)?;
            let mut object_id = [0u8; SYNC_ID_BYTES];
            fill_random(&mut object_id)?;
            let header = SyncChunkHeaderV1 {
                schema_version: envelope.schema_version,
                object_id: URL_SAFE_NO_PAD.encode(object_id),
                vault_id: envelope.vault_id.clone(),
                key_epoch: new_key.key_epoch,
            };
            encrypt_chunk(new_key, &header, &plaintext)
        })
        .collect()
}

pub fn encrypt_chunk(
    key: &VaultDataKeyV1,
    header: &SyncChunkHeaderV1,
    plaintext: &[u8],
) -> Result<SyncEnvelopeV1, SyncErrorV1> {
    header.validate().map_err(|_| SyncErrorV1::InvalidHeader)?;
    if plaintext.len() > SYNC_MAX_CHUNK_BYTES {
        return Err(SyncErrorV1::PayloadTooLarge);
    }
    let aad = sync_chunk_aad(header)?;
    let vault_id =
        decode_fixed::<SYNC_ID_BYTES>(&header.vault_id).map_err(|_| SyncErrorV1::InvalidHeader)?;
    if key.vault_id != vault_id || key.key_epoch != header.key_epoch {
        return Err(SyncErrorV1::InvalidKeyScope);
    }

    let mut nonce = [0u8; SYNC_NONCE_BYTES];
    fill_random(&mut nonce)?;
    let ciphertext = seal_with_nonce(&key.secret, &nonce, &aad, plaintext)?;
    let envelope = SyncEnvelopeV1 {
        schema_version: header.schema_version,
        object_id: header.object_id.clone(),
        vault_id: header.vault_id.clone(),
        key_epoch: header.key_epoch,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    envelope.validate().map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    Ok(envelope)
}

pub fn decrypt_chunk(
    key: &VaultDataKeyV1,
    envelope: &SyncEnvelopeV1,
) -> Result<Zeroizing<Vec<u8>>, SyncErrorV1> {
    envelope.validate().map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let header = envelope.header();
    let aad = sync_chunk_aad(&header)?;
    let vault_id = decode_fixed::<SYNC_ID_BYTES>(&header.vault_id)
        .map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    if key.vault_id != vault_id || key.key_epoch != header.key_epoch {
        return Err(SyncErrorV1::InvalidKeyScope);
    }
    let nonce = decode_fixed::<SYNC_NONCE_BYTES>(&envelope.nonce)
        .map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let ciphertext =
        decode_encoded(&envelope.ciphertext).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    open_with_nonce(&key.secret, &nonce, &aad, ciphertext)
}

pub(super) fn sync_chunk_aad(header: &SyncChunkHeaderV1) -> Result<Vec<u8>, SyncErrorV1> {
    header.validate().map_err(|_| SyncErrorV1::InvalidHeader)?;
    let object_id =
        decode_fixed::<SYNC_ID_BYTES>(&header.object_id).map_err(|_| SyncErrorV1::InvalidHeader)?;
    let vault_id =
        decode_fixed::<SYNC_ID_BYTES>(&header.vault_id).map_err(|_| SyncErrorV1::InvalidHeader)?;
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 4 + SYNC_ID_BYTES * 2 + 8);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(&header.schema_version.to_be_bytes());
    aad.extend_from_slice(&object_id);
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&header.key_epoch.to_be_bytes());
    Ok(aad)
}

fn derive_wrapping_key(
    root_key: &AccountRootKeyV1,
    vault_id: &[u8; SYNC_ID_BYTES],
    key_epoch: u64,
) -> Result<Zeroizing<[u8; SYNC_KEY_BYTES]>, SyncErrorV1> {
    let epoch = key_epoch.to_be_bytes();
    let prk = Salt::new(HKDF_SHA256, KEY_WRAP_SALT).extract(&root_key.secret[..]);
    let info: [&[u8]; 3] = [KEY_WRAP_INFO, vault_id, &epoch];
    let okm = prk
        .expand(&info, KeyBytes)
        .map_err(|_| SyncErrorV1::KeyDerivationFailed)?;
    let mut key = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    okm.fill(&mut key[..])
        .map_err(|_| SyncErrorV1::KeyDerivationFailed)?;
    Ok(key)
}

fn key_wrap_aad(vault_id: &[u8; SYNC_ID_BYTES], key_epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEY_WRAP_AAD_DOMAIN.len() + 4 + SYNC_ID_BYTES + 8);
    aad.extend_from_slice(KEY_WRAP_AAD_DOMAIN);
    aad.extend_from_slice(&SYNC_SCHEMA_VERSION_V1.to_be_bytes());
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

struct KeyBytes;

impl KeyType for KeyBytes {
    fn len(&self) -> usize {
        SYNC_KEY_BYTES
    }
}

pub(super) fn seal_with_nonce(
    key: &[u8; SYNC_KEY_BYTES],
    nonce: &[u8; SYNC_NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SyncErrorV1> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SyncErrorV1::InvalidKey)?;
    let nonce = XNonce::from(*nonce);
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    cipher
        .encrypt_in_place(&nonce, aad, &mut *buffer)
        .map_err(|_| SyncErrorV1::CipherFailure)?;
    Ok(buffer.as_slice().to_vec())
}

pub(super) fn open_with_nonce(
    key: &[u8; SYNC_KEY_BYTES],
    nonce: &[u8; SYNC_NONCE_BYTES],
    aad: &[u8],
    ciphertext: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, SyncErrorV1> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| SyncErrorV1::InvalidKey)?;
    let nonce = XNonce::from(*nonce);
    let mut plaintext = Zeroizing::new(ciphertext);
    cipher
        .decrypt_in_place(&nonce, aad, &mut *plaintext)
        .map_err(|_| SyncErrorV1::AuthenticationFailed)?;
    Ok(plaintext)
}

pub(crate) fn fill_random(output: &mut [u8]) -> Result<(), SyncErrorV1> {
    SystemRandom::new()
        .fill(output)
        .map_err(|_| SyncErrorV1::RandomnessUnavailable)
}

fn decode_encoded(value: &str) -> Result<Vec<u8>, SyncErrorV1> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SyncErrorV1::InvalidEnvelope)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], SyncErrorV1> {
    decode_encoded(value)?
        .try_into()
        .map_err(|_| SyncErrorV1::InvalidEnvelope)
}
