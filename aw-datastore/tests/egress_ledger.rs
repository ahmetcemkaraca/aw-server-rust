use aw_datastore::Datastore;
use aw_models::{
    EgressApprovalScopeV1, EgressOutcomeV1, EgressPolicyBundleV1, EgressPolicyV1,
    EgressMatchKindV1, EgressPatternV1, EgressReceiptV1, EgressRuleActionV1,
    EgressRuleV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
};
use chrono::{DateTime, Duration, Utc};

fn receipt() -> EgressReceiptV1 {
    EgressReceiptV1 {
        schema_version: 1,
        destination_id: "sync-relay".into(),
        purpose_id: "sync".into(),
        retention_id: "test-session".into(),
        allowed_fields: vec!["/timestamp".into(), "/app".into()],
        policy_version: 3,
        scope: EgressApprovalScopeV1::Once,
        decision: EgressOutcomeV1::Allow,
        created_at: DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    }
}

fn policy_parts() -> (SignedEgressPolicyBundleV1, EgressUserPolicyV1) {
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
    (
        SignedEgressPolicyBundleV1 {
            schema_version: 1,
            signer_key_id: "test-only".into(),
            bundle,
            signature: vec![0; 64],
        },
        user,
    )
}

#[test]
fn receipt_roundtrips_without_event_payloads_and_kill_switch_defaults_closed() {
    let store = Datastore::new_in_memory(false);
    assert!(store.egress_kill_switch().unwrap());
    store.record_egress_receipt(&receipt()).unwrap();
    let receipts = store.get_egress_receipts(10).unwrap();
    assert_eq!(receipts, vec![receipt()]);
    let serialized = serde_json::to_value(&receipts[0]).unwrap();
    assert!(serialized.get("payload").is_none());
    assert!(serialized.get("sanitized_payload").is_none());
    store.close();
}

#[test]
fn kill_switch_change_is_persistent_and_reversible() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    assert!(!store.egress_kill_switch().unwrap());
    store.set_egress_kill_switch(true).unwrap();
    assert!(store.egress_kill_switch().unwrap());
    store.close();
}

#[test]
fn egress_secrets_are_random_distinct_and_stable_in_the_vault() {
    let path = std::env::temp_dir().join(format!("peakactivity-egress-secrets-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store = Datastore::new(path.to_string_lossy().into_owned(), false);
    let first = store.get_or_create_egress_secrets().unwrap();
    let second = store.get_or_create_egress_secrets().unwrap();
    assert_eq!(first.alias_secret(), second.alias_secret());
    assert_eq!(first.approval_secret(), second.approval_secret());
    assert_ne!(first.alias_secret(), first.approval_secret());
    assert!(first.alias_secret().iter().any(|byte| *byte != 0));
    assert!(first.approval_secret().iter().any(|byte| *byte != 0));
    assert!(store.get_key_value("egress.alias_secret").is_err());
    assert!(store.set_key_value("egress.alias_secret", "attacker-controlled").is_err());
    store.close();
    let reopened = Datastore::new(path.to_string_lossy().into_owned(), false);
    let after_restart = reopened.get_or_create_egress_secrets().unwrap();
    assert_eq!(first.alias_secret(), after_restart.alias_secret());
    assert_eq!(first.approval_secret(), after_restart.approval_secret());
    reopened.close();
    drop(first);
    drop(second);
    drop(after_restart);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn one_time_approval_binds_payload_metadata_and_is_consumed_atomically() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let now = Utc::now();
    let tag = [42_u8; 32];
    let id = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::Once,
        tag, Some(now + Duration::minutes(5)), now,
    ).unwrap();
    assert!(store.consume_egress_approval(
        &id, "sync-relay", "sync", "test-session", 3, [0_u8; 32], now,
    ).is_err());
    store.consume_egress_approval(
        &id, "sync-relay", "sync", "test-session", 3, tag, now,
    ).unwrap();
    assert!(store.consume_egress_approval(
        &id, "sync-relay", "sync", "test-session", 3, tag, now,
    ).is_err());
    store.close();
}

#[test]
fn approval_metadata_is_listable_without_payload_tags_and_reports_scope_on_use() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let now = Utc::now();
    let tag = [31_u8; 32];
    let once_id = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::Once,
        tag, Some(now + Duration::minutes(5)), now,
    ).unwrap();
    let metadata = store.get_egress_approval(&once_id, now).unwrap().unwrap();
    assert_eq!(metadata.scope, EgressApprovalScopeV1::Once);
    assert_eq!(metadata.destination_id, "sync-relay");
    assert!(serde_json::to_value(&metadata).unwrap().get("payload_tag").is_none());
    let listed = store.get_egress_approvals(10, now).unwrap();
    assert_eq!(listed, vec![metadata]);
    assert_eq!(store.consume_egress_approval(
        &once_id, "sync-relay", "sync", "test-session", 3, tag, now,
    ).unwrap(), EgressApprovalScopeV1::Once);
    assert!(store.get_egress_approval(&once_id, now).unwrap().is_none());

    let reusable_id = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::TimeLimited,
        tag, Some(now + Duration::hours(1)), now,
    ).unwrap();
    assert_eq!(store.consume_egress_approval(
        &reusable_id, "sync-relay", "sync", "test-session", 3, tag, now,
    ).unwrap(), EgressApprovalScopeV1::TimeLimited);
    assert!(store.get_egress_approval(&reusable_id, now).unwrap().is_some());
    store.close();
}

#[test]
fn kill_switch_revokes_grants_and_expired_approvals_are_rejected() {
    let store = Datastore::new_in_memory(false);
    let now = Utc::now();
    store.set_egress_kill_switch(false).unwrap();
    let tag = [7_u8; 32];
    let id = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::DestinationSpecific,
        tag, None, now,
    ).unwrap();
    store.set_egress_kill_switch(true).unwrap();
    store.set_egress_kill_switch(false).unwrap();
    assert!(store.consume_egress_approval(
        &id, "sync-relay", "sync", "test-session", 3, tag, now,
    ).is_err());

    let expiring = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::Once,
        tag, Some(now + Duration::seconds(1)), now,
    ).unwrap();
    assert!(store.consume_egress_approval(
        &expiring, "sync-relay", "sync", "test-session", 3, tag, now + Duration::seconds(2),
    ).is_err());
    store.close();
}

#[test]
fn time_limited_approval_reuses_only_the_exact_scoped_payload_until_expiry() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let now = Utc::now();
    let tag = [9_u8; 32];
    let expires = now + Duration::hours(1);
    let id = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::TimeLimited,
        tag, Some(expires), now,
    ).unwrap();
    for _ in 0..2 {
        store.consume_egress_approval(
            &id, "sync-relay", "sync", "test-session", 3, tag, now,
        ).unwrap();
    }
    assert!(store.consume_egress_approval(
        &id, "sync-relay", "sync", "test-session", 3, [8_u8; 32], now,
    ).is_err());
    assert!(store.consume_egress_approval(
        &id, "sync-relay", "sync", "test-session", 3, tag, expires,
    ).is_err());
    store.close();
}

#[test]
fn vault_close_revokes_egress_approvals_across_reopen() {
    let path = std::env::temp_dir().join(format!("peakactivity-egress-approval-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store = Datastore::new(path.to_string_lossy().into_owned(), false);
    store.set_egress_kill_switch(false).unwrap();
    let now = Utc::now();
    let tag = [11_u8; 32];
    let id = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::DestinationSpecific,
        tag, None, now,
    ).unwrap();
    store.close();
    let reopened = Datastore::new(path.to_string_lossy().into_owned(), false);
    reopened.set_egress_kill_switch(false).unwrap();
    assert!(reopened.consume_egress_approval(
        &id, "sync-relay", "sync", "test-session", 3, tag, Utc::now(),
    ).is_err());
    reopened.close();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn policy_state_roundtrips_and_replaces_old_approval_scopes() {
    let store = Datastore::new_in_memory(false);
    assert!(store.get_egress_policy_state().unwrap().is_none());
    store.set_egress_kill_switch(false).unwrap();
    let now = Utc::now();
    let old_approval = store.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::DestinationSpecific,
        [5_u8; 32], None, now,
    ).unwrap();
    let (mut signed, user) = policy_parts();
    signed.bundle.version += 1;
    store.store_egress_policy_state(&signed, &user).unwrap();
    let stored = store.get_egress_policy_state().unwrap().unwrap();
    assert_eq!(stored, (signed, user));
    assert!(store.consume_egress_approval(
        &old_approval, "sync-relay", "sync", "test-session", 3, [5_u8; 32], now,
    ).is_err());
    store.close();
}

#[test]
fn restrictive_user_rules_persist_before_any_remote_bundle_is_trusted() {
    let store = Datastore::new_in_memory(false);
    let policy = EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: vec![EgressRuleV1 {
            pattern: EgressPatternV1 { kind: EgressMatchKindV1::Keyword, value: "medical visit".into() },
            action: EgressRuleActionV1::Deny,
        }],
        safe_zone_patterns: vec![],
        after_hours: None,
    };
    store.store_egress_user_policy(&policy).unwrap();
    assert_eq!(store.get_egress_user_policy().unwrap(), policy);
    assert!(store.get_egress_policy_state().unwrap().is_none());
    assert!(store.get_key_value("egress.user_policy").is_err());
    store.close();
}
