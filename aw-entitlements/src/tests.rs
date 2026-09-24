use super::{verify_entitlement, EntitlementAccessV1, EntitlementVerificationErrorV1};
use aw_models::{
    EntitlementClaimsV1, EntitlementRevocationSnapshotV1, EntitlementSigningPayloadV1,
    SignedEntitlementV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::BTreeMap;

const NOW: u64 = 1_900_000_000;

fn claims() -> EntitlementClaimsV1 {
    EntitlementClaimsV1 {
        schema_version: 1,
        entitlement_id: URL_SAFE_NO_PAD.encode([0x31; 16]),
        account_id: URL_SAFE_NO_PAD.encode([0x32; 16]),
        plan_id: "plus".into(),
        feature_ids: vec!["e2ee-sync".into()],
        issued_at: NOW - 60,
        expires_at: NOW + 100,
        grace_until: NOW + 3_600,
        device_limit: 3,
    }
}

fn signed_entitlement(seed: [u8; 32]) -> (SignedEntitlementV1, [u8; 32]) {
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let payload = EntitlementSigningPayloadV1 {
        key_id: "billing-key-1".into(),
        claims: claims(),
    };
    let signature = URL_SAFE_NO_PAD.encode(keypair.sign(&payload.signing_bytes().unwrap()).as_ref());
    let public_key = keypair.public_key().as_ref().try_into().unwrap();
    (SignedEntitlementV1 { payload, signature }, public_key)
}

fn signed_revocations(
    seed: [u8; 32],
    sequence: u64,
    revoked_entitlement_ids: Vec<String>,
) -> EntitlementRevocationSnapshotV1 {
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let mut snapshot = EntitlementRevocationSnapshotV1 {
        schema_version: 1,
        key_id: "billing-key-1".into(),
        sequence,
        issued_at: NOW - 30,
        expires_at: NOW + 1_000,
        revoked_entitlement_ids,
        signature: String::new(),
    };
    snapshot.signature = URL_SAFE_NO_PAD.encode(keypair.sign(&snapshot.signing_bytes().unwrap()).as_ref());
    snapshot
}

#[test]
fn verifies_signature_and_returns_current_or_grace_access() {
    let seed = [0x91; 32];
    let (token, public_key) = signed_entitlement(seed);
    let keys = BTreeMap::from([("billing-key-1".into(), public_key)]);

    let current = verify_entitlement(&token, &keys, NOW, None, 0).unwrap();
    assert_eq!(current.access, EntitlementAccessV1::Current);
    assert_eq!(current.claims.feature_ids, ["e2ee-sync"]);

    let grace = verify_entitlement(&token, &keys, NOW + 101, None, 0).unwrap();
    assert_eq!(grace.access, EntitlementAccessV1::Grace);
    assert_eq!(
        verify_entitlement(&token, &keys, NOW + 3_601, None, 0).unwrap_err(),
        EntitlementVerificationErrorV1::Expired,
    );
}

#[test]
fn forged_wrong_key_and_not_yet_valid_entitlements_are_rejected() {
    let seed = [0x92; 32];
    let (token, public_key) = signed_entitlement(seed);
    let keys = BTreeMap::from([("billing-key-1".into(), public_key)]);
    let mut forged = token.clone();
    forged.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert_eq!(
        verify_entitlement(&forged, &keys, NOW, None, 0).unwrap_err(),
        EntitlementVerificationErrorV1::InvalidSignature,
    );
    assert_eq!(
        verify_entitlement(&token, &BTreeMap::new(), NOW, None, 0).unwrap_err(),
        EntitlementVerificationErrorV1::UnknownKey,
    );
    assert_eq!(
        verify_entitlement(&token, &keys, NOW - 61, None, 0).unwrap_err(),
        EntitlementVerificationErrorV1::NotYetValid,
    );
}

#[test]
fn signed_revocations_and_minimum_sequence_are_enforced() {
    let seed = [0x93; 32];
    let (token, public_key) = signed_entitlement(seed);
    let keys = BTreeMap::from([("billing-key-1".into(), public_key)]);
    let revocations = signed_revocations(
        seed,
        8,
        vec![token.payload.claims.entitlement_id.clone()],
    );

    assert_eq!(
        verify_entitlement(&token, &keys, NOW, Some(&revocations), 9).unwrap_err(),
        EntitlementVerificationErrorV1::StaleRevocations,
    );
    assert_eq!(
        verify_entitlement(&token, &keys, NOW, Some(&revocations), 8).unwrap_err(),
        EntitlementVerificationErrorV1::Revoked,
    );

    let mut forged = revocations.clone();
    forged.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert_eq!(
        verify_entitlement(&token, &keys, NOW, Some(&forged), 0).unwrap_err(),
        EntitlementVerificationErrorV1::InvalidSignature,
    );
    assert_eq!(
        verify_entitlement(&token, &keys, NOW + 1_001, Some(&revocations), 0).unwrap_err(),
        EntitlementVerificationErrorV1::RevocationSnapshotExpired,
    );
    assert_eq!(
        verify_entitlement(&token, &keys, NOW, None, 8).unwrap_err(),
        EntitlementVerificationErrorV1::MissingRevocations,
    );
}

#[test]
fn shared_entitlement_vector_verifies_with_the_published_public_key() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../test-vectors/entitlement-v1.json"
    )).unwrap();
    let public_key: [u8; 32] = URL_SAFE_NO_PAD.decode(vector["public_key"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    let token: SignedEntitlementV1 = serde_json::from_value(vector["entitlement"].clone()).unwrap();
    let signing_bytes = String::from_utf8(token.payload.signing_bytes().unwrap()).unwrap();
    assert_eq!(signing_bytes, vector["signing_bytes"].as_str().unwrap());
    let keys = BTreeMap::from([(token.payload.key_id.clone(), public_key)]);
    let verified = verify_entitlement(
        &token,
        &keys,
        vector["now"].as_u64().unwrap(),
        None,
        0,
    ).unwrap();
    assert_eq!(verified.claims.plan_id, "plus");
}
