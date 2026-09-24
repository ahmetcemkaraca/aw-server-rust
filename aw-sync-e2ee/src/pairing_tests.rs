use crate::pairing::{
    begin_pairing, complete_pairing, confirm_pairing, derive_pairing_session,
    generate_device_identity, respond_to_pairing, transcript_bytes, verification_code,
};
use crate::{
    accept_key_transfer, create_key_transfer, create_vault_data_key, generate_account_root_key,
    unwrap_vault_data_key, DeviceIdentityV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::digest::{digest, SHA256};

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn pairing_transcript_and_code_match_the_shared_vector() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/sync-pairing-v1.json")).unwrap();
    let offer: aw_models::PairingOfferV1 =
        serde_json::from_value(vector["offer"].clone()).unwrap();
    offer.validate().unwrap();
    let transcript = transcript_bytes(&offer).unwrap();
    assert_eq!(encode_hex(&transcript), vector["transcript_hex"]);
    let hash = digest(&SHA256, &transcript);
    assert_eq!(encode_hex(hash.as_ref()), vector["transcript_hash_hex"]);
    let hash: [u8; 32] = hash.as_ref().try_into().unwrap();
    assert_eq!(verification_code(&hash), vector["verification_code"]);
}

#[test]
fn pairing_transcript_binds_both_ed25519_signing_keys() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/sync-pairing-v1.json")).unwrap();
    let mut offer: aw_models::PairingOfferV1 =
        serde_json::from_value(vector["offer"].clone()).unwrap();
    let original = transcript_bytes(&offer).unwrap();

    offer.issuer.ed25519_public_key = URL_SAFE_NO_PAD.encode([33u8; 32]);
    assert_ne!(transcript_bytes(&offer).unwrap(), original);
    offer.issuer.ed25519_public_key = vector["offer"]["issuer"]["ed25519_public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    offer.recipient.ed25519_public_key = URL_SAFE_NO_PAD.encode([34u8; 32]);
    assert_ne!(transcript_bytes(&offer).unwrap(), original);
}

#[test]
fn both_devices_must_confirm_the_same_offer_before_key_transfer() {
    let issuer = generate_device_identity().unwrap();
    let recipient = generate_device_identity().unwrap();
    let (invitation, issuer_ephemeral) =
        begin_pairing(&issuer, &recipient.public_identity()).unwrap();
    let (response, recipient_ephemeral) = respond_to_pairing(&recipient, &invitation).unwrap();
    let offer = complete_pairing(invitation, response).unwrap();
    let mut issuer_session =
        derive_pairing_session(&issuer, issuer_ephemeral, offer.clone()).unwrap();
    let mut recipient_session =
        derive_pairing_session(&recipient, recipient_ephemeral, offer.clone()).unwrap();
    assert_eq!(issuer_session.verification_code(), recipient_session.verification_code());

    let issuer_code = issuer_session.verification_code().to_owned();
    let mut wrong_code = issuer_code.clone().into_bytes();
    wrong_code[0] = if wrong_code[0] == b'0' { b'1' } else { b'0' };
    let wrong_code = String::from_utf8(wrong_code).unwrap();
    assert!(confirm_pairing(&mut issuer_session, &wrong_code, true).is_err());
    assert!(confirm_pairing(&mut issuer_session, &issuer_code, false).is_err());

    let issuer_confirmation = confirm_pairing(&mut issuer_session, &issuer_code, true).unwrap();
    let recipient_code = recipient_session.verification_code().to_owned();
    let recipient_confirmation =
        confirm_pairing(&mut recipient_session, &recipient_code, true).unwrap();
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([15u8; 16]);
    let (_, wrapped_key) = create_vault_data_key(&root, &vault_id, 1).unwrap();

    let transfer = create_key_transfer(
        &issuer_session,
        &recipient_confirmation,
        &root,
        &wrapped_key,
    )
    .unwrap();
    assert!(create_key_transfer(&issuer_session, &issuer_confirmation, &root, &wrapped_key).is_err());
    let imported = accept_key_transfer(
        &recipient_session,
        &issuer_confirmation,
        &transfer,
    )
    .unwrap();
    let unwrapped = unwrap_vault_data_key(&imported.account_root_key, &imported.wrapped_vault_key)
        .unwrap();
    assert_eq!(unwrapped.key_epoch(), 1);
}

#[test]
fn identity_key_changes_fail_closed_and_storage_roundtrips() {
    let issuer = generate_device_identity().unwrap();
    let recipient = generate_device_identity().unwrap();
    let stored_id: [u8; 16] = URL_SAFE_NO_PAD
        .decode(&recipient.public_identity().device_id)
        .unwrap()
        .try_into()
        .unwrap();
    let restored = DeviceIdentityV1::from_bytes(
        stored_id,
        recipient.secret_for_storage(),
        recipient.signing_seed_for_storage(),
    );
    assert_eq!(restored.public_identity(), recipient.public_identity());

    let (invitation, issuer_ephemeral) =
        begin_pairing(&issuer, &recipient.public_identity()).unwrap();
    let (response, recipient_ephemeral) = respond_to_pairing(&recipient, &invitation).unwrap();
    let valid_offer = complete_pairing(invitation, response).unwrap();
    let mut changed_identity = valid_offer.clone();
    changed_identity.recipient.x25519_public_key = URL_SAFE_NO_PAD.encode([33u8; 32]);
    let issuer_changed_view =
        derive_pairing_session(&issuer, issuer_ephemeral, changed_identity).unwrap();
    let recipient_valid_view =
        derive_pairing_session(&recipient, recipient_ephemeral, valid_offer).unwrap();
    assert_ne!(
        issuer_changed_view.verification_code(),
        recipient_valid_view.verification_code()
    );

    let (invitation, _issuer_ephemeral) =
        begin_pairing(&issuer, &recipient.public_identity()).unwrap();
    let (response, recipient_ephemeral) = respond_to_pairing(&recipient, &invitation).unwrap();
    let mut changed_identity = complete_pairing(invitation, response).unwrap();
    changed_identity.recipient.x25519_public_key = URL_SAFE_NO_PAD.encode([34u8; 32]);
    assert!(derive_pairing_session(
        &recipient,
        recipient_ephemeral,
        changed_identity
    )
    .is_err());
}
