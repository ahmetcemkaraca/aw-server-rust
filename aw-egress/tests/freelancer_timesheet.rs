use aw_datastore::Datastore;
use aw_egress::{policy_bundle_signing_bytes, verify_and_activate, EgressProxy, EgressTransport};
use aw_models::{
    ApprovedTimesheetV1, EgressApprovalScopeV1, EgressDestinationStatusV1,
    EgressDestinationV1, EgressOutcomeV1, EgressPolicyBundleV1, EgressPurposeV1,
    EgressReasonCodeV1, EgressRequestV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
};
use chrono::{DateTime, Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const TEST_SEED: [u8; 32] = [17; 32];

#[derive(Clone, Default)]
struct RecordingTransport(Arc<Mutex<Vec<Vec<u8>>>>);

impl EgressTransport for RecordingTransport {
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

fn policy_and_request() -> (aw_egress::VerifiedPolicyV1, EgressRequestV1, Vec<u8>) {
    policy_and_request_at_version(1)
}

fn policy_and_request_at_version(version: u64) -> (aw_egress::VerifiedPolicyV1, EgressRequestV1, Vec<u8>) {
    let destination = EgressDestinationV1 {
        id: "freelancer-client".into(),
        status: EgressDestinationStatusV1::Experimental,
        https_origin: Some("https://client.example.test".into()),
        allowed_purposes: vec!["freelancer-timesheet-v1".into()],
    };
    let purpose = EgressPurposeV1 {
        id: "freelancer-timesheet-v1".into(),
        destination_id: destination.id.clone(),
        endpoint_path: "/timesheets".into(),
        retention_id: "client-session".into(),
        retention_disclosure: "Synthetic test only; no real request is sent.".into(),
        allowed_fields: [
            "/approved_duration_seconds", "/date", "/project_alias",
            "/schema_version", "/user_note",
        ].into_iter().map(str::to_string).collect(),
    };
    let bundle = EgressPolicyBundleV1 {
        schema_version: 1,
        version,
        hard_deny_version: 1,
        destinations: vec![destination],
        purposes: vec![purpose],
        organization_rules: vec![],
    };
    let user = EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: vec![],
        safe_zone_patterns: vec![],
        after_hours: None,
    };
    let keypair = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "freelancer-test-key".into(),
        bundle,
        signature: Vec::new(),
    };
    signed.signature = keypair.sign(&policy_bundle_signing_bytes(&signed).unwrap()).as_ref().to_vec();
    let keys = HashMap::from([("freelancer-test-key".into(), keypair.public_key().as_ref().to_vec())]);
    let active = verify_and_activate(&signed, &user, &keys, None).unwrap();

    let artifact = ApprovedTimesheetV1 {
        schema_version: 1,
        project_alias: "project-9af31c".into(),
        date: "2026-09-23".into(),
        approved_duration_seconds: 18_000,
        user_note: Some("Approved sprint work".into()),
    }.artifact_bytes().unwrap();
    let request = EgressRequestV1 {
        schema_version: 1,
        destination_id: "freelancer-client".into(),
        purpose_id: "freelancer-timesheet-v1".into(),
        retention_id: "client-session".into(),
        payload: serde_json::from_slice(&artifact).unwrap(),
    };
    (active, request, artifact)
}

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc)
}

#[test]
fn approved_timesheet_sends_only_exact_canonical_bytes_once() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let transport = RecordingTransport::default();
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone());
    let (policy, request, artifact) = policy_and_request();
    let now = now();
    let preview = proxy.preview(&policy, request, now, 0);
    assert_eq!(preview.outcome, EgressOutcomeV1::Allow);
    assert_eq!(serde_json::to_vec(preview.sanitized_payload.as_ref().unwrap()).unwrap(), artifact);

    let guard = proxy.begin_send().unwrap();
    assert_eq!(
        guard.send_approval(&policy, &preview.preview_id, "missing-approval", now, 0),
        Err(EgressReasonCodeV1::ApprovalExpired),
    );
    assert!(transport.0.lock().unwrap().is_empty());

    let approved = guard.approve(
        &policy, &preview.preview_id, EgressApprovalScopeV1::Once,
        Some(now + Duration::minutes(5)), now, 0,
    ).unwrap();
    let approval_id = approved.approval_id().to_string();
    let preview_id = preview.preview_id;
    let receipt = guard.send_approval(&policy, &preview_id, &approval_id, now, 0).unwrap();
    assert_eq!(receipt.destination_id, "freelancer-client");
    assert_eq!(receipt.purpose_id, "freelancer-timesheet-v1");
    assert_eq!(receipt.retention_id, "client-session");
    assert_eq!(transport.0.lock().unwrap().as_slice(), &[artifact]);
    assert!(guard.send_approval(&policy, &preview_id, &approval_id, now, 0).is_err());
    assert_eq!(transport.0.lock().unwrap().len(), 1);
    store.close();
}

#[test]
fn an_approved_timesheet_cannot_be_reused_for_a_changed_duration() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let transport = RecordingTransport::default();
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone());
    let (policy, request, artifact) = policy_and_request();
    let now = now();
    let original = proxy.preview(&policy, request.clone(), now, 0);
    let guard = proxy.begin_send().unwrap();
    let approved = guard.approve(
        &policy, &original.preview_id, EgressApprovalScopeV1::TimeLimited,
        Some(now + Duration::minutes(5)), now, 0,
    ).unwrap();
    let approval_id = approved.approval_id().to_string();

    let mut changed_request = request;
    changed_request.payload["approved_duration_seconds"] = serde_json::json!(17_999);
    let changed = proxy.preview(&policy, changed_request, now + Duration::seconds(1), 0);
    assert_eq!(changed.outcome, EgressOutcomeV1::Allow);
    assert!(guard.send_approval(
        &policy, &changed.preview_id, &approval_id, now + Duration::seconds(1), 0,
    ).is_err());
    assert!(transport.0.lock().unwrap().is_empty());

    guard.send_approval(&policy, &original.preview_id, &approval_id, now, 0).unwrap();
    assert_eq!(transport.0.lock().unwrap().as_slice(), &[artifact]);
    store.close();
}

#[test]
fn a_stale_policy_and_a_locked_vault_never_reach_transport() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let transport = RecordingTransport::default();
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone());
    let (policy, request, _) = policy_and_request();
    let (new_policy, _, _) = policy_and_request_at_version(2);
    let now = now();
    let preview = proxy.preview(&policy, request, now, 0);
    let guard = proxy.begin_send().unwrap();
    let approved = guard.approve(
        &policy, &preview.preview_id, EgressApprovalScopeV1::Once,
        Some(now + Duration::minutes(5)), now, 0,
    ).unwrap();
    assert_eq!(guard.send_approval(
        &new_policy, &preview.preview_id, approved.approval_id(), now, 0,
    ), Err(EgressReasonCodeV1::PolicyChanged));
    assert!(transport.0.lock().unwrap().is_empty());
    store.close();

    let locked = Datastore::new_locked();
    let locked_transport = RecordingTransport::default();
    let locked_proxy = EgressProxy::with_transport(locked.clone(), locked_transport.clone());
    let (policy, request, _) = policy_and_request();
    let denied = locked_proxy.preview(&policy, request, now, 0);
    assert_eq!(denied.outcome, EgressOutcomeV1::Deny);
    assert_eq!(denied.reason_codes, vec![EgressReasonCodeV1::KillSwitch]);
    assert!(locked_transport.0.lock().unwrap().is_empty());
    locked.close();
}
