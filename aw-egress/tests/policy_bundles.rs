use aw_egress::{policy_bundle_signing_bytes, policy_diff, verify_and_activate, PolicyBundleErrorV1};
use aw_models::{
    EgressPolicyBundleV1, EgressPolicyV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;

const TEST_SEED: [u8; 32] = [42; 32];

fn bundle_and_user() -> (EgressPolicyBundleV1, EgressUserPolicyV1) {
    let vector: serde_json::Value = serde_json::from_str(include_str!("../../test-vectors/privacy-firewall-v1.json")).unwrap();
    let active: EgressPolicyV1 = serde_json::from_value(vector["policy"].clone()).unwrap();
    let bundle = EgressPolicyBundleV1 {
        schema_version: 1,
        version: active.version,
        hard_deny_version: active.hard_deny_version,
        destinations: active.destinations,
        purposes: active.purposes,
        organization_rules: active.organization_rules,
    };
    let user = EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: active.user_rules,
        safe_zone_patterns: active.safe_zone_patterns,
        after_hours: active.after_hours,
    };
    (bundle, user)
}

fn signed_bundle() -> (SignedEgressPolicyBundleV1, HashMap<String, Vec<u8>>) {
    let (bundle, _) = bundle_and_user();
    let keypair = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "test-policy-key".into(),
        bundle,
        signature: Vec::new(),
    };
    signed.signature = keypair.sign(&policy_bundle_signing_bytes(&signed).unwrap()).as_ref().to_vec();
    let keys = HashMap::from([("test-policy-key".into(), keypair.public_key().as_ref().to_vec())]);
    (signed, keys)
}

#[test]
fn verifies_signature_and_keeps_user_policy_separate() {
    let (signed, keys) = signed_bundle();
    let (_, user) = bundle_and_user();
    let verified = verify_and_activate(&signed, &user, &keys, None).unwrap();
    assert_eq!(verified.policy().version, signed.bundle.version);
    assert_eq!(verified.policy().user_rules, user.user_rules);
}

#[test]
fn signing_bytes_use_canonical_sorted_json_for_cross_platform_verification() {
    let (signed, _) = signed_bundle();
    let bytes = policy_bundle_signing_bytes(&signed).unwrap();
    let prefix = b"PeakActivity:EgressPolicyBundleV1\0";
    let body_start = prefix.len() + 2 + signed.signer_key_id.len() + 1;
    let canonical = serde_json::to_vec(&serde_json::to_value(&signed.bundle).unwrap()).unwrap();
    assert_eq!(&bytes[..prefix.len()], prefix);
    assert_eq!(&bytes[body_start..], canonical.as_slice());
}

#[test]
fn rejects_unknown_keys_tampering_replay_and_hard_deny_downgrade() {
    let (signed, keys) = signed_bundle();
    let (_, user) = bundle_and_user();
    let empty = HashMap::new();
    assert!(matches!(verify_and_activate(&signed, &user, &empty, None), Err(PolicyBundleErrorV1::UnknownSigner)));

    let mut tampered = signed.clone();
    tampered.bundle.destinations[0].https_origin = Some("https://evil.example".into());
    assert!(matches!(verify_and_activate(&tampered, &user, &keys, None), Err(PolicyBundleErrorV1::InvalidSignature)));

    let current = verify_and_activate(&signed, &user, &keys, None).unwrap();
    assert!(matches!(verify_and_activate(&signed, &user, &keys, Some(current.policy())), Err(PolicyBundleErrorV1::StaleVersion)));

    let mut current_policy = current.policy().clone();
    current_policy.hard_deny_version = 2;
    let mut downgraded = signed.clone();
    downgraded.bundle.version += 1;
    let keypair = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
    downgraded.signature = keypair.sign(&policy_bundle_signing_bytes(&downgraded).unwrap()).as_ref().to_vec();
    assert!(matches!(verify_and_activate(&downgraded, &user, &keys, Some(&current_policy)), Err(PolicyBundleErrorV1::HardDenyRollback)));
}

#[test]
fn policy_diff_reports_destination_purpose_and_rule_changes_deterministically() {
    let (signed, _) = signed_bundle();
    let previous_bundle = signed.bundle;
    let mut next_bundle = previous_bundle.clone();
    next_bundle.version += 1;
    next_bundle.destinations[0].status = aw_models::EgressDestinationStatusV1::Planned;
    next_bundle.destinations[0].https_origin = None;
    next_bundle.purposes[0].retention_disclosure = "Changed retention terms".into();
    next_bundle.organization_rules.push(aw_models::EgressRuleV1 {
        pattern: aw_models::EgressPatternV1 {
            kind: aw_models::EgressMatchKindV1::Field,
            value: "/app".into(),
        },
        action: aw_models::EgressRuleActionV1::DropField,
    });
    let (_, user) = bundle_and_user();
    let previous = EgressPolicyV1::from_bundle_and_user(&previous_bundle, &user).unwrap();
    let next = EgressPolicyV1::from_bundle_and_user(&next_bundle, &user).unwrap();
    let diff = policy_diff(&previous, &next);
    assert_eq!(diff.from_version, previous.version);
    assert_eq!(diff.to_version, next.version);
    assert_eq!(diff.changed_destinations[0].id, "sync-relay");
    assert_eq!(diff.changed_purposes[0].id, "sync");
    assert_eq!(diff.added_organization_rules.len(), 1);
}
