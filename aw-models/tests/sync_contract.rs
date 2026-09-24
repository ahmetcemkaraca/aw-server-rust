use aw_models::{
    DevicePublicIdentityV1, EncryptedKeyTransferV1, PairingConfirmationV1, PairingInvitationV1,
    PairingOfferV1, PairingResponseV1, RecoveryKitV1, SyncBucketDescriptorV1, SyncEnvelopeV1, SyncOperationKindV1,
    SyncRelayOperationV1, SyncRelayRequestV1, SyncRelayResponseV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

#[test]
fn sync_envelope_matches_the_v1_wire_vector() {
    let vector: Value = serde_json::from_str(include_str!("../../test-vectors/sync-envelope-v1.json")).unwrap();
    let envelope: SyncEnvelopeV1 = serde_json::from_value(vector["valid"].clone()).unwrap();
    envelope.validate().unwrap();
    assert_eq!(serde_json::to_value(envelope).unwrap(), vector["valid"]);
}

#[test]
fn relay_envelope_never_serializes_synthetic_plaintext_fields() {
    let vector: Value = serde_json::from_str(include_str!("../../test-vectors/sync-envelope-v1.json")).unwrap();
    let envelope: SyncEnvelopeV1 = serde_json::from_value(vector["valid"].clone()).unwrap();
    let serialized = serde_json::to_string(&envelope).unwrap();
    let keys = serde_json::from_str::<Value>(&serialized).unwrap();
    let mut actual = keys.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    actual.sort();
    assert_eq!(actual, vector["relay_fields"].as_array().unwrap().iter().map(|value| value.as_str().unwrap().to_string()).collect::<Vec<_>>());
    assert!(!serialized.contains(vector["synthetic_plaintext"].as_str().unwrap()));
}

#[test]
fn relay_envelope_rejects_unrecognized_fields() {
    let vector: Value = serde_json::from_str(include_str!("../../test-vectors/sync-envelope-v1.json")).unwrap();
    let mut envelope = vector["valid"].clone();
    envelope["hostname"] = Value::String("SYNTHETIC_PRIVATE_HOST".into());
    assert!(serde_json::from_value::<SyncEnvelopeV1>(envelope).is_err());
}

#[test]
fn versioned_relay_requests_are_opaque_and_list_pages_are_ordered() {
    let vault_id = URL_SAFE_NO_PAD.encode([0x11; 16]);
    let first = SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([0x12; 16]),
        vault_id: vault_id.clone(),
        key_epoch: 4,
        nonce: URL_SAFE_NO_PAD.encode([0x13; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([0x14; 32]),
    };
    let put = SyncRelayRequestV1 {
        schema_version: 1,
        operation: SyncRelayOperationV1::PutIfAbsent,
        object_id: Some(first.object_id.clone()),
        vault_id: Some(vault_id.clone()),
        envelope: Some(first.clone()),
        cursor: None,
        limit: None,
    };
    put.validate().unwrap();
    let serialized = serde_json::to_string(&put).unwrap();
    assert!(!serialized.contains("synthetic-private-title"));
    let mut unrecognized = serde_json::to_value(&put).unwrap();
    unrecognized["private_title"] = Value::String("synthetic-private-title".into());
    assert!(serde_json::from_value::<SyncRelayRequestV1>(unrecognized).is_err());

    let mut mismatched = put.clone();
    mismatched.object_id = Some(URL_SAFE_NO_PAD.encode([0x15; 16]));
    assert!(mismatched.validate().is_err());

    let list = SyncRelayRequestV1 {
        schema_version: 1,
        operation: SyncRelayOperationV1::ListOpaqueHeads,
        object_id: None,
        vault_id: Some(vault_id.clone()),
        envelope: None,
        cursor: None,
        limit: Some(2),
    };
    list.validate().unwrap();
    let second = SyncEnvelopeV1 {
        object_id: URL_SAFE_NO_PAD.encode([0x16; 16]),
        ..first.clone()
    };
    let response = SyncRelayResponseV1 {
        schema_version: 1,
        next_cursor: Some(second.object_id.clone()),
        objects: vec![first, second],
        ..Default::default()
    };
    response.validate_for(&list).unwrap();
    let mut unordered = response;
    unordered.objects.reverse();
    assert!(unordered.validate_for(&list).is_err());
}

#[test]
fn sync_envelope_rejects_unknown_versions_and_malformed_encoded_fields() {
    let vector: Value = serde_json::from_str(include_str!("../../test-vectors/sync-envelope-v1.json")).unwrap();
    for case in vector["invalid"].as_array().unwrap() {
        let envelope: SyncEnvelopeV1 = serde_json::from_value(case["envelope"].clone()).unwrap();
        assert!(envelope.validate().is_err(), "{}", case["id"].as_str().unwrap());
    }
}

#[test]
fn unknown_sync_operation_names_fail_during_deserialization() {
    assert!(serde_json::from_str::<SyncOperationKindV1>("\"unknown-operation\"").is_err());
}

#[test]
fn public_identity_pairing_and_recovery_headers_validate_lengths_and_parameters() {
    let id = URL_SAFE_NO_PAD.encode([1u8; 16]);
    let key = URL_SAFE_NO_PAD.encode([2u8; 32]);
    let nonce = URL_SAFE_NO_PAD.encode([3u8; 24]);
    let ciphertext = URL_SAFE_NO_PAD.encode([4u8; 48]);
    DevicePublicIdentityV1 {
        schema_version: 1,
        device_id: id.clone(),
        x25519_public_key: key.clone(),
        ed25519_public_key: key.clone(),
    }
    .validate()
    .unwrap();
    PairingOfferV1 {
        schema_version: 1,
        offer_id: id.clone(),
        issuer: DevicePublicIdentityV1 {
            schema_version: 1,
            device_id: id.clone(),
            x25519_public_key: key.clone(),
            ed25519_public_key: key.clone(),
        },
        recipient: DevicePublicIdentityV1 {
            schema_version: 1,
            device_id: URL_SAFE_NO_PAD.encode([7u8; 16]),
            x25519_public_key: URL_SAFE_NO_PAD.encode([8u8; 32]),
            ed25519_public_key: URL_SAFE_NO_PAD.encode([9u8; 32]),
        },
        issuer_ephemeral_key: key.clone(),
        recipient_ephemeral_key: key.clone(),
        challenge: URL_SAFE_NO_PAD.encode([6u8; 32]),
    }
    .validate()
    .unwrap();
    let short_challenge = PairingOfferV1 {
        schema_version: 1,
        offer_id: id.clone(),
        issuer: DevicePublicIdentityV1 {
            schema_version: 1,
            device_id: id.clone(),
            x25519_public_key: key.clone(),
            ed25519_public_key: key.clone(),
        },
        recipient: DevicePublicIdentityV1 {
            schema_version: 1,
            device_id: URL_SAFE_NO_PAD.encode([7u8; 16]),
            x25519_public_key: URL_SAFE_NO_PAD.encode([8u8; 32]),
            ed25519_public_key: URL_SAFE_NO_PAD.encode([9u8; 32]),
        },
        issuer_ephemeral_key: key.clone(),
        recipient_ephemeral_key: key.clone(),
        challenge: nonce.clone(),
    };
    assert!(short_challenge.validate().is_err());
    RecoveryKitV1 {
        schema_version: 1,
        kdf: "argon2id-v19".into(),
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
        salt: URL_SAFE_NO_PAD.encode([5u8; 16]),
        nonce,
        ciphertext,
    }
    .validate()
    .unwrap();

    let unsupported = RecoveryKitV1 {
        schema_version: 1,
        kdf: "argon2id-v19".into(),
        memory_kib: 1024,
        iterations: 1,
        parallelism: 1,
        salt: URL_SAFE_NO_PAD.encode([5u8; 16]),
        nonce: URL_SAFE_NO_PAD.encode([3u8; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([4u8; 48]),
    };
    assert!(unsupported.validate().is_err());
}

#[test]
fn pairing_exchange_wire_phases_validate_public_fields_and_sizes() {
    let issuer = DevicePublicIdentityV1 {
        schema_version: 1,
        device_id: URL_SAFE_NO_PAD.encode([1u8; 16]),
        x25519_public_key: URL_SAFE_NO_PAD.encode([2u8; 32]),
        ed25519_public_key: URL_SAFE_NO_PAD.encode([3u8; 32]),
    };
    let recipient = DevicePublicIdentityV1 {
        schema_version: 1,
        device_id: URL_SAFE_NO_PAD.encode([3u8; 16]),
        x25519_public_key: URL_SAFE_NO_PAD.encode([4u8; 32]),
        ed25519_public_key: URL_SAFE_NO_PAD.encode([5u8; 32]),
    };
    let offer_id = URL_SAFE_NO_PAD.encode([5u8; 16]);
    let invitation = PairingInvitationV1 {
        schema_version: 1,
        offer_id: offer_id.clone(),
        issuer: issuer.clone(),
        recipient_device_id: recipient.device_id.clone(),
        issuer_ephemeral_key: URL_SAFE_NO_PAD.encode([6u8; 32]),
        challenge: URL_SAFE_NO_PAD.encode([7u8; 32]),
    };
    invitation.validate().unwrap();
    let mut self_invitation = invitation.clone();
    self_invitation.recipient_device_id = issuer.device_id.clone();
    assert!(self_invitation.validate().is_err());
    let response = PairingResponseV1 {
        schema_version: 1,
        offer_id: offer_id.clone(),
        recipient: recipient.clone(),
        recipient_ephemeral_key: URL_SAFE_NO_PAD.encode([8u8; 32]),
    };
    response.validate().unwrap();
    let offer = PairingOfferV1 {
        schema_version: 1,
        offer_id: offer_id.clone(),
        issuer,
        recipient,
        issuer_ephemeral_key: invitation.issuer_ephemeral_key.clone(),
        recipient_ephemeral_key: response.recipient_ephemeral_key.clone(),
        challenge: invitation.challenge.clone(),
    };
    offer.validate().unwrap();
    let mut self_offer = offer.clone();
    self_offer.recipient.device_id = self_offer.issuer.device_id.clone();
    assert!(self_offer.validate().is_err());

    PairingConfirmationV1 {
        schema_version: 1,
        offer_id: offer_id.clone(),
        device_id: URL_SAFE_NO_PAD.encode([3u8; 16]),
        transcript_hash: URL_SAFE_NO_PAD.encode([9u8; 32]),
        authenticator: URL_SAFE_NO_PAD.encode([10u8; 32]),
    }
    .validate()
    .unwrap();
    EncryptedKeyTransferV1 {
        schema_version: 1,
        offer_id,
        nonce: URL_SAFE_NO_PAD.encode([11u8; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([12u8; 144]),
    }
    .validate()
    .unwrap();

    let mut short_challenge = invitation;
    short_challenge.challenge = URL_SAFE_NO_PAD.encode([7u8; 24]);
    assert!(short_challenge.validate().is_err());
}

#[test]
fn device_signing_key_and_bucket_descriptor_validate_lengths_and_fields() {
    let identity = DevicePublicIdentityV1 {
        schema_version: 1,
        device_id: URL_SAFE_NO_PAD.encode([1u8; 16]),
        x25519_public_key: URL_SAFE_NO_PAD.encode([2u8; 32]),
        ed25519_public_key: URL_SAFE_NO_PAD.encode([3u8; 32]),
    };
    identity.validate().unwrap();

    let mut invalid_identity = identity;
    invalid_identity.ed25519_public_key = URL_SAFE_NO_PAD.encode([4u8; 31]);
    assert!(invalid_identity.validate().is_err());

    let bucket = SyncBucketDescriptorV1 {
        bucket_type: "app".into(),
        client: "PeakActivity".into(),
        data: std::collections::BTreeMap::new(),
    };
    bucket.validate().unwrap();
    let mut wire = serde_json::to_value(bucket).unwrap();
    wire["hostname"] = serde_json::Value::String("SYNTHETIC_HOST".into());
    assert!(serde_json::from_value::<SyncBucketDescriptorV1>(wire).is_err());
}
