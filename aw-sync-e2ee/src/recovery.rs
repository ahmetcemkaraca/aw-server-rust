use argon2::{Algorithm, Argon2, Params, Version};
use aw_models::{RecoveryKitV1, SYNC_KEY_BYTES, SYNC_NONCE_BYTES, SYNC_SCHEMA_VERSION_V1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::crypto::{decode_key_material_bundle, encode_key_material_bundle, open_with_nonce, seal_with_nonce};
use crate::{AccountRootKeyV1, SyncErrorV1, SyncKeyMaterialBundleV1, WrappedVaultDataKeyV1};

const RECOVERY_KDF: &str = "argon2id-v19";
const RECOVERY_MEMORY_KIB: u32 = 65_536;
const RECOVERY_ITERATIONS: u32 = 3;
const RECOVERY_PARALLELISM: u32 = 4;
const RECOVERY_DOMAIN: &[u8] = b"PeakActivity-Sync-Recovery-v1\0";

pub fn create_recovery_kit(
    account_root_key: &AccountRootKeyV1,
    wrapped_vault_key: &WrappedVaultDataKeyV1,
) -> Result<(String, RecoveryKitV1), SyncErrorV1> {
    wrapped_vault_key.validate()?;
    let mut phrase_entropy = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; SYNC_NONCE_BYTES];
    fill_random(&mut phrase_entropy[..])?;
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    let phrase = URL_SAFE_NO_PAD.encode(&phrase_entropy[..]);

    let key = derive_recovery_key(&phrase, &salt)?;
    let plaintext = encode_key_material_bundle(account_root_key, wrapped_vault_key)?;
    let aad = recovery_aad(&salt);
    let ciphertext = seal_with_nonce(&key, &nonce, &aad, &plaintext)?;
    let kit = RecoveryKitV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        kdf: RECOVERY_KDF.into(),
        memory_kib: RECOVERY_MEMORY_KIB,
        iterations: RECOVERY_ITERATIONS,
        parallelism: RECOVERY_PARALLELISM,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    kit.validate().map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    Ok((phrase, kit))
}

pub fn open_recovery_kit(
    kit: &RecoveryKitV1,
    phrase: &str,
) -> Result<SyncKeyMaterialBundleV1, SyncErrorV1> {
    kit.validate().map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    decode_fixed::<SYNC_KEY_BYTES>(phrase).map_err(|_| SyncErrorV1::InvalidRecoveryPhrase)?;
    let salt = decode_fixed::<16>(&kit.salt).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let nonce = decode_fixed::<SYNC_NONCE_BYTES>(&kit.nonce).map_err(|_| SyncErrorV1::InvalidEnvelope)?;
    let ciphertext = decode_encoded(&kit.ciphertext)?;
    let key = derive_recovery_key(phrase, &salt)?;
    let plaintext = open_with_nonce(&key, &nonce, &recovery_aad(&salt), ciphertext)?;
    decode_key_material_bundle(&plaintext)
}

fn derive_recovery_key(
    phrase: &str,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; SYNC_KEY_BYTES]>, SyncErrorV1> {
    let params = Params::new(
        RECOVERY_MEMORY_KIB,
        RECOVERY_ITERATIONS,
        RECOVERY_PARALLELISM,
        Some(SYNC_KEY_BYTES),
    )
    .map_err(|_| SyncErrorV1::RecoveryKdfFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    argon2
        .hash_password_into(phrase.as_bytes(), salt, &mut output[..])
        .map_err(|_| SyncErrorV1::RecoveryKdfFailed)?;
    Ok(output)
}

fn recovery_aad(salt: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECOVERY_DOMAIN.len() + 4 + RECOVERY_KDF.len() + 1 + 12 + 16);
    aad.extend_from_slice(RECOVERY_DOMAIN);
    aad.extend_from_slice(&SYNC_SCHEMA_VERSION_V1.to_be_bytes());
    aad.extend_from_slice(RECOVERY_KDF.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&RECOVERY_MEMORY_KIB.to_be_bytes());
    aad.extend_from_slice(&RECOVERY_ITERATIONS.to_be_bytes());
    aad.extend_from_slice(&RECOVERY_PARALLELISM.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn fill_random(output: &mut [u8]) -> Result<(), SyncErrorV1> {
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
