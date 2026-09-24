use aw_models::{
    DevicePublicIdentityV1, EncryptedKeyTransferV1, PairingConfirmationV1,
    PairingInvitationV1, PairingOfferV1, PairingResponseV1, SYNC_CHALLENGE_BYTES,
    SYNC_ID_BYTES, SYNC_KEY_BYTES, SYNC_NONCE_BYTES, SYNC_SCHEMA_VERSION_V1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use ring::hmac::{self, HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{
    decode_key_material_bundle, encode_key_material_bundle, open_with_nonce, seal_with_nonce,
};
use crate::{
    AccountRootKeyV1, SyncErrorV1, WrappedVaultDataKeyV1,
};

const PAIRING_DOMAIN: &[u8] = b"PeakActivity-Sync-Pairing-v1\0";
const PAIRING_KDF_INFO: &[u8] = b"PeakActivity/Sync/Pairing/v1";
const CONFIRMATION_DOMAIN: &[u8] = b"PeakActivity-Sync-Pairing-Confirm-v1\0";
const KEY_TRANSFER_DOMAIN: &[u8] = b"PeakActivity-Sync-KeyTransfer-v1\0";

pub struct DeviceIdentityV1 {
    device_id: [u8; SYNC_ID_BYTES],
    private_key: StaticSecret,
    signing_seed: Zeroizing<[u8; SYNC_KEY_BYTES]>,
    signing_public_key: [u8; SYNC_KEY_BYTES],
}

impl DeviceIdentityV1 {
    pub fn from_bytes(
        device_id: [u8; SYNC_ID_BYTES],
        private_key: Zeroizing<[u8; SYNC_KEY_BYTES]>,
        signing_seed: Zeroizing<[u8; SYNC_KEY_BYTES]>,
    ) -> Self {
        let signing_pair = Ed25519KeyPair::from_seed_unchecked(&signing_seed[..])
            .expect("an Ed25519 seed is exactly 32 bytes");
        let signing_public_key = signing_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("an Ed25519 public key is exactly 32 bytes");
        Self {
            device_id,
            private_key: StaticSecret::from(*private_key),
            signing_seed,
            signing_public_key,
        }
    }

    pub fn public_identity(&self) -> DevicePublicIdentityV1 {
        DevicePublicIdentityV1 {
            schema_version: SYNC_SCHEMA_VERSION_V1,
            device_id: URL_SAFE_NO_PAD.encode(self.device_id),
            x25519_public_key: URL_SAFE_NO_PAD
                .encode(PublicKey::from(&self.private_key).to_bytes()),
            ed25519_public_key: URL_SAFE_NO_PAD.encode(self.signing_public_key),
        }
    }

    pub fn secret_for_storage(&self) -> Zeroizing<[u8; SYNC_KEY_BYTES]> {
        Zeroizing::new(self.private_key.to_bytes())
    }

    pub fn signing_seed_for_storage(&self) -> Zeroizing<[u8; SYNC_KEY_BYTES]> {
        Zeroizing::new(*self.signing_seed)
    }

    pub(crate) fn sign_manifest_bytes(&self, message: &[u8]) -> [u8; 64] {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&self.signing_seed[..])
            .expect("an Ed25519 seed is exactly 32 bytes");
        key_pair.sign(message).as_ref().try_into()
            .expect("an Ed25519 signature is exactly 64 bytes")
    }

    pub fn device_id_bytes(&self) -> &[u8; SYNC_ID_BYTES] {
        &self.device_id
    }
}

pub struct PairingEphemeralKeyV1 {
    private_key: StaticSecret,
    public_key: [u8; SYNC_KEY_BYTES],
}

pub struct PairingSessionV1 {
    offer_id: [u8; SYNC_ID_BYTES],
    local_device_id: [u8; SYNC_ID_BYTES],
    peer_device_id: [u8; SYNC_ID_BYTES],
    transcript_hash: [u8; SYNC_KEY_BYTES],
    verification_code: String,
    transfer_key: Zeroizing<[u8; SYNC_KEY_BYTES]>,
    locally_confirmed: bool,
}

impl PairingSessionV1 {
    pub fn verification_code(&self) -> &str {
        &self.verification_code
    }
}

pub fn generate_device_identity() -> Result<DeviceIdentityV1, SyncErrorV1> {
    let mut device_id = [0u8; SYNC_ID_BYTES];
    let mut private_key = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    let mut signing_seed = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    fill_random(&mut device_id)?;
    fill_random(&mut private_key[..])?;
    fill_random(&mut signing_seed[..])?;
    Ok(DeviceIdentityV1::from_bytes(device_id, private_key, signing_seed))
}

pub fn begin_pairing(
    issuer: &DeviceIdentityV1,
    recipient: &DevicePublicIdentityV1,
) -> Result<(PairingInvitationV1, PairingEphemeralKeyV1), SyncErrorV1> {
    recipient
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    let recipient_id = decode_fixed::<SYNC_ID_BYTES>(&recipient.device_id)?;
    if recipient_id == issuer.device_id {
        return Err(SyncErrorV1::InvalidPairing);
    }
    let (ephemeral, ephemeral_public) = new_ephemeral_key()?;
    let mut offer_id = [0u8; SYNC_ID_BYTES];
    let mut challenge = [0u8; SYNC_CHALLENGE_BYTES];
    fill_random(&mut offer_id)?;
    fill_random(&mut challenge)?;
    let invitation = PairingInvitationV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        offer_id: URL_SAFE_NO_PAD.encode(offer_id),
        issuer: issuer.public_identity(),
        recipient_device_id: recipient.device_id.clone(),
        issuer_ephemeral_key: URL_SAFE_NO_PAD.encode(ephemeral_public),
        challenge: URL_SAFE_NO_PAD.encode(challenge),
    };
    invitation
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    Ok((invitation, ephemeral))
}

pub fn respond_to_pairing(
    recipient: &DeviceIdentityV1,
    invitation: &PairingInvitationV1,
) -> Result<(PairingResponseV1, PairingEphemeralKeyV1), SyncErrorV1> {
    invitation
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    if decode_fixed::<SYNC_ID_BYTES>(&invitation.recipient_device_id)? != recipient.device_id
        || invitation.issuer.device_id == invitation.recipient_device_id
    {
        return Err(SyncErrorV1::InvalidPairing);
    }
    let (ephemeral, ephemeral_public) = new_ephemeral_key()?;
    let response = PairingResponseV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        offer_id: invitation.offer_id.clone(),
        recipient: recipient.public_identity(),
        recipient_ephemeral_key: URL_SAFE_NO_PAD.encode(ephemeral_public),
    };
    response
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    Ok((response, ephemeral))
}

pub fn complete_pairing(
    invitation: PairingInvitationV1,
    response: PairingResponseV1,
) -> Result<PairingOfferV1, SyncErrorV1> {
    invitation
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    response
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    if invitation.offer_id != response.offer_id
        || invitation.recipient_device_id != response.recipient.device_id
        || invitation.issuer.device_id == response.recipient.device_id
    {
        return Err(SyncErrorV1::InvalidPairing);
    }
    let offer = PairingOfferV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        offer_id: invitation.offer_id,
        issuer: invitation.issuer,
        recipient: response.recipient,
        issuer_ephemeral_key: invitation.issuer_ephemeral_key,
        recipient_ephemeral_key: response.recipient_ephemeral_key,
        challenge: invitation.challenge,
    };
    offer
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    Ok(offer)
}

pub fn derive_pairing_session(
    identity: &DeviceIdentityV1,
    ephemeral: PairingEphemeralKeyV1,
    offer: PairingOfferV1,
) -> Result<PairingSessionV1, SyncErrorV1> {
    offer
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    let own_identity = identity.public_identity();
    let (local, peer, local_ephemeral, peer_ephemeral) = if own_identity == offer.issuer {
        (
            &offer.issuer,
            &offer.recipient,
            &offer.issuer_ephemeral_key,
            &offer.recipient_ephemeral_key,
        )
    } else if own_identity == offer.recipient {
        (
            &offer.recipient,
            &offer.issuer,
            &offer.recipient_ephemeral_key,
            &offer.issuer_ephemeral_key,
        )
    } else {
        return Err(SyncErrorV1::InvalidPairing);
    };

    let expected_local_ephemeral = decode_fixed::<SYNC_KEY_BYTES>(local_ephemeral)?;
    if expected_local_ephemeral != ephemeral.public_key {
        return Err(SyncErrorV1::InvalidPairing);
    }
    let peer_ephemeral = decode_fixed::<SYNC_KEY_BYTES>(peer_ephemeral)?;
    let peer_public = PublicKey::from(peer_ephemeral);
    let shared = ephemeral.private_key.diffie_hellman(&peer_public);
    if !shared.was_contributory() {
        return Err(SyncErrorV1::InvalidPairing);
    }

    let transcript = transcript_bytes(&offer)?;
    let hash = digest(&SHA256, &transcript);
    let mut transcript_hash = [0u8; SYNC_KEY_BYTES];
    transcript_hash.copy_from_slice(hash.as_ref());
    let shared_secret = Zeroizing::new(shared.to_bytes());
    let transfer_key = derive_transfer_key(&transcript_hash, &shared_secret)?;

    Ok(PairingSessionV1 {
        offer_id: decode_fixed::<SYNC_ID_BYTES>(&offer.offer_id)?,
        local_device_id: decode_fixed::<SYNC_ID_BYTES>(&local.device_id)?,
        peer_device_id: decode_fixed::<SYNC_ID_BYTES>(&peer.device_id)?,
        transcript_hash,
        verification_code: verification_code(&transcript_hash),
        transfer_key,
        locally_confirmed: false,
    })
}

pub fn confirm_pairing(
    session: &mut PairingSessionV1,
    displayed_code: &str,
    user_confirmed: bool,
) -> Result<PairingConfirmationV1, SyncErrorV1> {
    if !user_confirmed || displayed_code != session.verification_code {
        return Err(SyncErrorV1::PairingRejected);
    }
    session.locally_confirmed = true;
    Ok(PairingConfirmationV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        offer_id: URL_SAFE_NO_PAD.encode(session.offer_id),
        device_id: URL_SAFE_NO_PAD.encode(session.local_device_id),
        transcript_hash: URL_SAFE_NO_PAD.encode(session.transcript_hash),
        authenticator: URL_SAFE_NO_PAD.encode(confirmation_mac(
            &session.transfer_key,
            &session.transcript_hash,
            &session.local_device_id,
        )),
    })
}

pub fn create_key_transfer(
    session: &PairingSessionV1,
    peer_confirmation: &PairingConfirmationV1,
    root_key: &AccountRootKeyV1,
    wrapped_vault_key: &WrappedVaultDataKeyV1,
) -> Result<EncryptedKeyTransferV1, SyncErrorV1> {
    verify_peer_confirmation(session, peer_confirmation)?;
    wrapped_vault_key.validate()?;
    let plaintext = encode_key_material_bundle(root_key, wrapped_vault_key)?;

    let mut nonce = [0u8; SYNC_NONCE_BYTES];
    fill_random(&mut nonce)?;
    let aad = key_transfer_aad(session);
    let ciphertext = seal_with_nonce(&session.transfer_key, &nonce, &aad, &plaintext)?;
    let transfer = EncryptedKeyTransferV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        offer_id: URL_SAFE_NO_PAD.encode(session.offer_id),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    transfer
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    Ok(transfer)
}

pub fn accept_key_transfer(
    session: &PairingSessionV1,
    peer_confirmation: &PairingConfirmationV1,
    transfer: &EncryptedKeyTransferV1,
) -> Result<crate::SyncKeyMaterialBundleV1, SyncErrorV1> {
    verify_peer_confirmation(session, peer_confirmation)?;
    transfer
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    if transfer.offer_id != URL_SAFE_NO_PAD.encode(session.offer_id) {
        return Err(SyncErrorV1::InvalidPairing);
    }
    let nonce = decode_fixed::<SYNC_NONCE_BYTES>(&transfer.nonce)?;
    let ciphertext = decode_encoded(&transfer.ciphertext)?;
    let plaintext = open_with_nonce(
        &session.transfer_key,
        &nonce,
        &key_transfer_aad(session),
        ciphertext,
    )?;
    decode_key_material_bundle(&plaintext)
}

fn verify_peer_confirmation(
    session: &PairingSessionV1,
    confirmation: &PairingConfirmationV1,
) -> Result<(), SyncErrorV1> {
    if !session.locally_confirmed {
        return Err(SyncErrorV1::PairingNotConfirmed);
    }
    confirmation
        .validate()
        .map_err(|_| SyncErrorV1::InvalidPairing)?;
    if confirmation.offer_id != URL_SAFE_NO_PAD.encode(session.offer_id)
        || confirmation.device_id != URL_SAFE_NO_PAD.encode(session.peer_device_id)
        || confirmation.transcript_hash != URL_SAFE_NO_PAD.encode(session.transcript_hash)
    {
        return Err(SyncErrorV1::InvalidPairing);
    }
    let key = hmac::Key::new(HMAC_SHA256, &session.transfer_key[..]);
    let message = confirmation_message(&session.transcript_hash, &session.peer_device_id);
    let tag = decode_fixed::<SYNC_KEY_BYTES>(&confirmation.authenticator)?;
    hmac::verify(&key, &message, &tag).map_err(|_| SyncErrorV1::InvalidPairing)
}

fn confirmation_mac(
    key: &[u8; SYNC_KEY_BYTES],
    transcript_hash: &[u8; SYNC_KEY_BYTES],
    device_id: &[u8; SYNC_ID_BYTES],
) -> [u8; SYNC_KEY_BYTES] {
    let key = hmac::Key::new(HMAC_SHA256, key);
    let message = confirmation_message(transcript_hash, device_id);
    let mut mac = [0u8; SYNC_KEY_BYTES];
    mac.copy_from_slice(hmac::sign(&key, &message).as_ref());
    mac
}

fn confirmation_message(
    transcript_hash: &[u8; SYNC_KEY_BYTES],
    device_id: &[u8; SYNC_ID_BYTES],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(CONFIRMATION_DOMAIN.len() + SYNC_KEY_BYTES + SYNC_ID_BYTES);
    message.extend_from_slice(CONFIRMATION_DOMAIN);
    message.extend_from_slice(transcript_hash);
    message.extend_from_slice(device_id);
    message
}

pub(super) fn transcript_bytes(offer: &PairingOfferV1) -> Result<Vec<u8>, SyncErrorV1> {
    let issuer_id = decode_fixed::<SYNC_ID_BYTES>(&offer.issuer.device_id)?;
    let recipient_id = decode_fixed::<SYNC_ID_BYTES>(&offer.recipient.device_id)?;
    let issuer_identity_key = decode_fixed::<SYNC_KEY_BYTES>(&offer.issuer.x25519_public_key)?;
    let issuer_signing_key = decode_fixed::<SYNC_KEY_BYTES>(&offer.issuer.ed25519_public_key)?;
    let recipient_identity_key = decode_fixed::<SYNC_KEY_BYTES>(&offer.recipient.x25519_public_key)?;
    let recipient_signing_key = decode_fixed::<SYNC_KEY_BYTES>(&offer.recipient.ed25519_public_key)?;
    let issuer_ephemeral_key = decode_fixed::<SYNC_KEY_BYTES>(&offer.issuer_ephemeral_key)?;
    let recipient_ephemeral_key = decode_fixed::<SYNC_KEY_BYTES>(&offer.recipient_ephemeral_key)?;
    let challenge = decode_fixed::<SYNC_CHALLENGE_BYTES>(&offer.challenge)?;

    let mut transcript = Vec::with_capacity(PAIRING_DOMAIN.len() + 4 + 16 + 16 + 32 * 7);
    transcript.extend_from_slice(PAIRING_DOMAIN);
    transcript.extend_from_slice(&offer.schema_version.to_be_bytes());
    transcript.extend_from_slice(&issuer_id);
    transcript.extend_from_slice(&recipient_id);
    transcript.extend_from_slice(&issuer_identity_key);
    transcript.extend_from_slice(&issuer_signing_key);
    transcript.extend_from_slice(&recipient_identity_key);
    transcript.extend_from_slice(&recipient_signing_key);
    transcript.extend_from_slice(&issuer_ephemeral_key);
    transcript.extend_from_slice(&recipient_ephemeral_key);
    transcript.extend_from_slice(&challenge);
    Ok(transcript)
}

pub(super) fn verification_code(transcript_hash: &[u8; SYNC_KEY_BYTES]) -> String {
    let numeric_code = u32::from_be_bytes(transcript_hash[..4].try_into().unwrap()) % 100_000_000;
    format!("{numeric_code:08}")
}

fn derive_transfer_key(
    transcript_hash: &[u8; SYNC_KEY_BYTES],
    shared_secret: &[u8; SYNC_KEY_BYTES],
) -> Result<Zeroizing<[u8; SYNC_KEY_BYTES]>, SyncErrorV1> {
    let prk = Salt::new(HKDF_SHA256, transcript_hash).extract(shared_secret);
    let okm = prk
        .expand(&[PAIRING_KDF_INFO], KeyBytes)
        .map_err(|_| SyncErrorV1::KeyDerivationFailed)?;
    let mut key = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    okm.fill(&mut key[..])
        .map_err(|_| SyncErrorV1::KeyDerivationFailed)?;
    Ok(key)
}

fn key_transfer_aad(session: &PairingSessionV1) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEY_TRANSFER_DOMAIN.len() + 4 + SYNC_ID_BYTES + SYNC_KEY_BYTES);
    aad.extend_from_slice(KEY_TRANSFER_DOMAIN);
    aad.extend_from_slice(&SYNC_SCHEMA_VERSION_V1.to_be_bytes());
    aad.extend_from_slice(&session.offer_id);
    aad.extend_from_slice(&session.transcript_hash);
    aad
}

fn new_ephemeral_key() -> Result<(PairingEphemeralKeyV1, [u8; SYNC_KEY_BYTES]), SyncErrorV1> {
    let mut raw = Zeroizing::new([0u8; SYNC_KEY_BYTES]);
    fill_random(&mut raw[..])?;
    let private_key = StaticSecret::from(*raw);
    let public_key = PublicKey::from(&private_key).to_bytes();
    Ok((PairingEphemeralKeyV1 { private_key, public_key }, public_key))
}

fn fill_random(output: &mut [u8]) -> Result<(), SyncErrorV1> {
    SystemRandom::new()
        .fill(output)
        .map_err(|_| SyncErrorV1::RandomnessUnavailable)
}

fn decode_encoded(value: &str) -> Result<Vec<u8>, SyncErrorV1> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SyncErrorV1::InvalidPairing)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], SyncErrorV1> {
    decode_encoded(value)?
        .try_into()
        .map_err(|_| SyncErrorV1::InvalidPairing)
}

struct KeyBytes;

impl KeyType for KeyBytes {
    fn len(&self) -> usize {
        SYNC_KEY_BYTES
    }
}
