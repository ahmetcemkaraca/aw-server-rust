use aw_datastore::Datastore;
use aw_egress::{
    verify_and_activate, EgressProxy, EgressTransport,
};
use aw_models::{
    EgressDestinationV1, EgressOutcomeV1, EgressPolicyBundleV1,
    EgressMatchKindV1, EgressPatternV1, EgressPolicyV1, EgressPurposeV1,
    EgressReasonCodeV1, EgressRequestV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
};
use chrono::{DateTime, Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

const TEST_SEED: [u8; 32] = [42; 32];

#[derive(Clone, Default)]
struct FakeTransport(Arc<Mutex<Vec<Vec<u8>>>>);

impl EgressTransport for FakeTransport {
    fn send(
        &self,
        _destination: &EgressDestinationV1,
        _purpose: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<(), EgressReasonCodeV1> {
        self.0.lock().unwrap().push(payload.to_vec());
        Ok(())
    }
}

struct BlockingTransport {
    started: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl EgressTransport for BlockingTransport {
    fn send(
        &self,
        _destination: &EgressDestinationV1,
        _purpose: &EgressPurposeV1,
        _payload: &[u8],
    ) -> Result<(), EgressReasonCodeV1> {
        self.started.send(()).map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
        self.release.lock().unwrap().recv().map_err(|_| EgressReasonCodeV1::NetworkUnavailable)
    }
}

struct FailingTransport;

impl EgressTransport for FailingTransport {
    fn send(
        &self,
        _destination: &EgressDestinationV1,
        _purpose: &EgressPurposeV1,
        _payload: &[u8],
    ) -> Result<(), EgressReasonCodeV1> {
        Err(EgressReasonCodeV1::NetworkUnavailable)
    }
}

fn policy() -> (aw_egress::VerifiedPolicyV1, EgressRequestV1) {
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
    let keypair = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "test-policy-key".into(),
        bundle,
        signature: Vec::new(),
    };
    signed.signature = keypair.sign(&aw_egress::policy_bundle_signing_bytes(&signed).unwrap()).as_ref().to_vec();
    let keys = HashMap::from([("test-policy-key".into(), keypair.public_key().as_ref().to_vec())]);
    let verified = verify_and_activate(&signed, &user, &keys, None).unwrap();
    let request: EgressRequestV1 = serde_json::from_value(
        vector["cases"].as_array().unwrap().iter()
            .find(|case| case["id"] == "purpose-field-allowlist").unwrap()["request"].clone(),
    ).unwrap();
    (verified, request)
}

#[test]
fn only_the_exact_approved_preview_reaches_the_transport_and_receipt() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let transport = FakeTransport::default();
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone());
    let (policy, request) = policy();
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc);

    let preview = proxy.preview(&policy, request, now, 0);
    assert_eq!(preview.outcome, EgressOutcomeV1::Allow);
    let payload = preview.sanitized_payload.clone().unwrap();
    let approved = proxy.approve(
        &policy, &preview.preview_id, aw_models::EgressApprovalScopeV1::Once,
        Some(now + Duration::minutes(5)), now, 0,
    ).unwrap();
    let receipt = proxy.send(&policy, approved, now, 0).unwrap();
    assert_eq!(receipt.decision, EgressOutcomeV1::Allow);
    assert_eq!(transport.0.lock().unwrap().as_slice(), &[serde_json::to_vec(&payload).unwrap()]);
    let receipts = store.get_egress_receipts(10).unwrap();
    assert_eq!(receipts, vec![receipt]);
    assert!(serde_json::to_value(&receipts[0]).unwrap().get("payload").is_none());
    store.close();
}

#[test]
fn kill_switch_blocks_transport_even_with_a_valid_approval() {
    let store = Datastore::new_in_memory(false);
    let transport = FakeTransport::default();
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone());
    let (policy, request) = policy();
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc);
    let preview = proxy.preview(&policy, request, now, 0);
    assert_eq!(preview.outcome, EgressOutcomeV1::Deny);
    assert_eq!(preview.reason_codes, vec![EgressReasonCodeV1::KillSwitch]);
    assert!(transport.0.lock().unwrap().is_empty());
    store.close();
}

#[test]
fn kill_switch_waits_for_in_flight_send_and_blocks_the_next_one() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let proxy = EgressProxy::with_transport(store.clone(), BlockingTransport {
        started: started_tx,
        release: Mutex::new(release_rx),
    });
    let (policy, request) = policy();
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc);
    let preview = proxy.preview(&policy, request.clone(), now, 0);
    let approved = proxy.approve(
        &policy, &preview.preview_id, aw_models::EgressApprovalScopeV1::Once,
        Some(now + Duration::minutes(5)), now, 0,
    ).unwrap();
    let send_proxy = proxy.clone();
    let send_policy = policy.clone();
    let send_thread = std::thread::spawn(move || send_proxy.send(&send_policy, approved, now, 0));
    started_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();

    let switch_proxy = proxy.clone();
    let switch_thread = std::thread::spawn(move || switch_proxy.set_kill_switch(true));
    release_tx.send(()).unwrap();
    assert_eq!(send_thread.join().unwrap().unwrap().decision, EgressOutcomeV1::Allow);
    switch_thread.join().unwrap().unwrap();
    assert!(proxy.kill_switch_enabled().unwrap());
    let denied = proxy.preview(&policy, request, now, 0);
    assert_eq!(denied.outcome, EgressOutcomeV1::Deny);
    assert_eq!(denied.reason_codes, vec![EgressReasonCodeV1::KillSwitch]);
    store.close();
}

#[test]
fn failed_transport_does_not_record_an_allow_receipt() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let proxy = EgressProxy::with_transport(store.clone(), FailingTransport);
    let (policy, request) = policy();
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc);
    let preview = proxy.preview(&policy, request, now, 0);
    let approved = proxy.approve(
        &policy, &preview.preview_id, aw_models::EgressApprovalScopeV1::Once,
        Some(now + Duration::minutes(5)), now, 0,
    ).unwrap();
    assert!(proxy.send(&policy, approved, now, 0).is_err());
    assert!(store.get_egress_receipts(10).unwrap().is_empty());
    store.close();
}

#[test]
fn time_limited_approval_reuses_only_the_same_sanitized_payload() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let proxy = EgressProxy::with_transport(store.clone(), FakeTransport::default());
    let (policy, request) = policy();
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc);
    let preview = proxy.preview(&policy, request.clone(), now, 0);
    let approval = proxy.approve(
        &policy,
        &preview.preview_id,
        aw_models::EgressApprovalScopeV1::TimeLimited,
        Some(now + Duration::hours(1)),
        now,
        0,
    ).unwrap();
    let approval_id = approval.approval_id().to_string();
    assert_eq!(proxy.send(&policy, approval, now, 0).unwrap().scope, aw_models::EgressApprovalScopeV1::TimeLimited);

    let next_preview = proxy.preview(&policy, request.clone(), now + Duration::seconds(1), 0);
    let receipt = proxy.send_approval(
        &policy, &next_preview.preview_id, &approval_id, now + Duration::seconds(1), 0,
    ).unwrap();
    assert_eq!(receipt.scope, aw_models::EgressApprovalScopeV1::TimeLimited);

    let mut changed = request;
    changed.payload["app"] = serde_json::json!("Different Editor");
    let changed_preview = proxy.preview(&policy, changed, now + Duration::seconds(2), 0);
    assert!(proxy.send_approval(
        &policy, &changed_preview.preview_id, &approval_id, now + Duration::seconds(2), 0,
    ).is_err());
    store.close();
}

#[test]
fn user_policy_diff_must_be_accepted_against_the_same_base() {
    let store = Datastore::new_in_memory(false);
    let proxy = EgressProxy::with_transport(store.clone(), FakeTransport::default());
    let (verified, _) = policy();
    let current = verified.policy().clone();
    let current_user = EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: current.user_rules.clone(),
        safe_zone_patterns: current.safe_zone_patterns.clone(),
        after_hours: current.after_hours.clone(),
    };
    let mut draft = current_user.clone();
    draft.safe_zone_patterns.push(EgressPatternV1 {
        kind: EgressMatchKindV1::Application,
        value: "Home Office".into(),
    });
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc);

    let stale_preview = proxy.preview_user_policy(&current, &current_user, &draft, now).unwrap();
    let mut changed = current.clone();
    changed.version += 1;
    assert!(proxy.accept_user_policy(&stale_preview.preview_id, &changed, now).is_err());

    let preview = proxy.preview_user_policy(&current, &current_user, &draft, now).unwrap();
    assert_eq!(preview.diff.added_safe_zone_patterns, vec![draft.safe_zone_patterns[1].clone()]);
    let (expected, accepted) = proxy.accept_user_policy(&preview.preview_id, &current, now).unwrap();
    assert_eq!(expected, current_user);
    assert_eq!(accepted, draft);
    assert!(proxy.accept_user_policy(&preview.preview_id, &current, now).is_err());
    store.close();
}
