use aw_datastore::Datastore;
use aw_egress::{policy_bundle_signing_bytes, verify_and_activate, EgressProxy, EgressTransport};
use aw_models::{
    ApprovedTimesheetV1, EgressApprovalScopeV1, EgressDestinationStatusV1,
    EgressDestinationV1, EgressOutcomeV1, EgressPolicyBundleV1, EgressPurposeV1,
    EgressReasonCodeV1, EgressRequestV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
    EntitlementClaimsV1, EntitlementRevocationSnapshotV1, EntitlementSigningPayloadV1,
    SignedEntitlementV1, FREELANCER_TIMESHEET_EGRESS_PURPOSE_V1,
};
use aw_entitlements::{EntitlementSourceV1, RuntimeFeatureAccessV1, StoredEntitlementV1, ENTITLEMENT_REVOCATION_SCOPE_V1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::collections::{BTreeMap, HashMap};
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
    policy_and_request_for(version, FREELANCER_TIMESHEET_EGRESS_PURPOSE_V1, &[])
}

fn policy_and_request_for(version: u64, purpose_id: &str, extra_fields: &[&str]) -> (aw_egress::VerifiedPolicyV1, EgressRequestV1, Vec<u8>) {
    let destination = EgressDestinationV1 {
        id: "freelancer-client".into(),
        status: EgressDestinationStatusV1::Experimental,
        https_origin: Some("https://client.example.test".into()),
        allowed_purposes: vec![purpose_id.into()],
    };
    let mut purpose = EgressPurposeV1 {
        id: purpose_id.into(),
        destination_id: destination.id.clone(),
        endpoint_path: "/timesheets".into(),
        retention_id: "client-session".into(),
        retention_disclosure: "Synthetic test only; no real request is sent.".into(),
        allowed_fields: [
            "/approved_duration_seconds", "/date", "/project_alias",
            "/schema_version", "/user_note",
        ].into_iter().map(str::to_string).collect(),
    };
    purpose.allowed_fields.extend(extra_fields.iter().map(|field| (*field).to_owned()));
    purpose.allowed_fields.sort();
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
        purpose_id: purpose_id.into(),
        retention_id: "client-session".into(),
        payload: serde_json::from_slice(&artifact).unwrap(),
    };
    (active, request, artifact)
}

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc)
}

#[derive(Default)]
struct MemoryEntitlementSource {
    proof: Mutex<Option<StoredEntitlementV1>>,
    floor: Mutex<u64>,
}

impl EntitlementSourceV1 for MemoryEntitlementSource {
    fn load(&self) -> Result<Option<StoredEntitlementV1>, &'static str> { Ok(self.proof.lock().unwrap().clone()) }
    fn save(&self, proof: &StoredEntitlementV1) -> Result<(), &'static str> {
        *self.proof.lock().unwrap() = Some(proof.clone()); Ok(())
    }
    fn revocation_floor(&self, scope: &str) -> Result<u64, &'static str> {
        assert_eq!(scope, ENTITLEMENT_REVOCATION_SCOPE_V1); Ok(*self.floor.lock().unwrap())
    }
    fn advance_revocation_floor(&self, scope: &str, sequence: u64) -> Result<(), &'static str> {
        assert_eq!(scope, ENTITLEMENT_REVOCATION_SCOPE_V1);
        let mut floor = self.floor.lock().unwrap(); *floor = (*floor).max(sequence); Ok(())
    }
}

fn sign_proof(proof: &mut StoredEntitlementV1) {
    let signer = Ed25519KeyPair::from_seed_unchecked(&[0xB1; 32]).unwrap();
    proof.entitlement.signature = URL_SAFE_NO_PAD.encode(signer.sign(&proof.entitlement.payload.signing_bytes().unwrap()).as_ref());
    if let Some(snapshot) = &mut proof.revocations {
        snapshot.signature = URL_SAFE_NO_PAD.encode(signer.sign(&snapshot.signing_bytes().unwrap()).as_ref());
    }
}

fn signed_freelancer_proof() -> StoredEntitlementV1 {
    let timestamp = u64::try_from(now().timestamp()).unwrap();
    let mut proof = StoredEntitlementV1 {
        entitlement: SignedEntitlementV1 {
            payload: EntitlementSigningPayloadV1 {
                key_id: "freelancer-billing-key".into(),
                claims: EntitlementClaimsV1 { schema_version: 1,
                    entitlement_id: URL_SAFE_NO_PAD.encode([0x41; 16]), account_id: URL_SAFE_NO_PAD.encode([0x42; 16]),
                    plan_id: "freelancer".into(), feature_ids: vec!["freelancer-workspace".into()],
                    issued_at: timestamp - 60, expires_at: timestamp + 60, grace_until: timestamp + 3600, device_limit: 3 },
            },
            signature: String::new(),
        },
        revocations: Some(EntitlementRevocationSnapshotV1 { schema_version: 1, key_id: "freelancer-billing-key".into(),
            sequence: 1, issued_at: timestamp - 60, expires_at: timestamp + 7200,
            revoked_entitlement_ids: vec![], signature: String::new() }),
    };
    sign_proof(&mut proof); proof
}

fn access_with_proof(proof: StoredEntitlementV1) -> Arc<RuntimeFeatureAccessV1> {
    let source = Arc::new(MemoryEntitlementSource::default());
    *source.proof.lock().unwrap() = Some(proof);
    let signer = Ed25519KeyPair::from_seed_unchecked(&[0xB1; 32]).unwrap();
    Arc::new(RuntimeFeatureAccessV1::new(BTreeMap::from([("freelancer-billing-key".into(), signer.public_key().as_ref().try_into().unwrap())]), 0, source))
}

fn approve_request(proxy: &EgressProxy, policy: &aw_egress::VerifiedPolicyV1, request: EgressRequestV1) -> (String, aw_egress::ApprovedEgress) {
    let preview = proxy.preview(policy, request, now(), 0);
    assert_eq!(preview.outcome, EgressOutcomeV1::Allow);
    let approved = proxy.approve(policy, &preview.preview_id, EgressApprovalScopeV1::TimeLimited,
        Some(now() + Duration::minutes(5)), now(), 0).unwrap();
    (preview.preview_id, approved)
}

fn assert_all_sends_denied(proxy: &EgressProxy, policy: &aw_egress::VerifiedPolicyV1, request: EgressRequestV1, reason: EgressReasonCodeV1) {
    let (preview_id, approved) = approve_request(proxy, policy, request.clone());
    assert_eq!(proxy.send_approval(policy, &preview_id, approved.approval_id(), now(), 0), Err(reason));
    assert_eq!(proxy.begin_send().unwrap().send_approval(policy, &preview_id, approved.approval_id(), now(), 0), Err(reason));
    assert_eq!(proxy.send(policy, approved, now(), 0), Err(reason));
    let (_, approved) = approve_request(proxy, policy, request);
    assert_eq!(proxy.begin_send().unwrap().send(policy, approved, now(), 0), Err(reason));
}

#[test]
fn freelancer_delivery_denies_unconfigured_and_invalid_signed_access_at_every_send() {
    let current = signed_freelancer_proof();
    let mut wrong_feature = current.clone();
    wrong_feature.entitlement.payload.claims.plan_id = "plus".into();
    wrong_feature.entitlement.payload.claims.feature_ids = vec!["e2ee-sync".into()];
    sign_proof(&mut wrong_feature);
    let mut offline = current.clone();
    offline.entitlement.payload.claims.plan_id = "local-pro".into();
    offline.entitlement.payload.claims.feature_ids = vec!["advanced-reports".into()];
    offline.revocations = None;
    sign_proof(&mut offline);
    let mut expired = current.clone();
    expired.entitlement.payload.claims.expires_at = u64::try_from(now().timestamp()).unwrap() - 2;
    expired.entitlement.payload.claims.grace_until = u64::try_from(now().timestamp()).unwrap() - 1;
    sign_proof(&mut expired);
    let mut revoked = current.clone();
    revoked.revocations.as_mut().unwrap().revoked_entitlement_ids = vec![revoked.entitlement.payload.claims.entitlement_id.clone()];
    sign_proof(&mut revoked);
    let mut missing = current;
    missing.revocations = None;
    for proof in [None, Some(wrong_feature), Some(offline), Some(expired), Some(revoked), Some(missing)] {
        let store = Datastore::new_in_memory(false);
        store.set_egress_kill_switch(false).unwrap();
        let transport = RecordingTransport::default();
        let access = proof.map(access_with_proof).unwrap_or_else(|| Arc::default());
        let proxy = EgressProxy::with_transport(store.clone(), transport.clone()).with_sync_access(access);
        let (policy, request, _) = policy_and_request();
        assert_all_sends_denied(&proxy, &policy, request, EgressReasonCodeV1::ApprovalRequired);
        assert!(transport.0.lock().unwrap().is_empty());
        assert!(store.get_egress_receipts(10).unwrap().is_empty());
        store.close();
    }
}

#[test]
fn freelancer_current_and_grace_access_send_exact_approved_artifacts_through_every_guard() {
    for grace in [false, true] {
        let mut proof = signed_freelancer_proof();
        if grace {
            proof.entitlement.payload.claims.expires_at = u64::try_from(now().timestamp()).unwrap() - 1;
            sign_proof(&mut proof);
        }
        let store = Datastore::new_in_memory(false);
        store.set_egress_kill_switch(false).unwrap();
        let transport = RecordingTransport::default();
        let proxy = EgressProxy::with_transport(store.clone(), transport.clone()).with_sync_access(access_with_proof(proof));
        let (policy, request, artifact) = policy_and_request();
        let (preview_id, approved) = approve_request(&proxy, &policy, request.clone());
        proxy.send_approval(&policy, &preview_id, approved.approval_id(), now(), 0).unwrap();
        proxy.begin_send().unwrap().send_approval(&policy, &preview_id, approved.approval_id(), now(), 0).unwrap();
        proxy.send(&policy, approved, now(), 0).unwrap();
        let (_, approved) = approve_request(&proxy, &policy, request);
        proxy.begin_send().unwrap().send(&policy, approved, now(), 0).unwrap();
        assert_eq!(transport.0.lock().unwrap().as_slice(), &[artifact.clone(), artifact.clone(), artifact.clone(), artifact]);
        store.close();
    }
}

#[test]
fn freelancer_delivery_rejects_raw_fields_even_when_the_signed_policy_allows_them() {
    for field in ["window_title", "events", "client_identity"] {
        let store = Datastore::new_in_memory(false);
        store.set_egress_kill_switch(false).unwrap();
        let transport = RecordingTransport::default();
        let proxy = EgressProxy::with_transport(store.clone(), transport.clone()).with_sync_access(access_with_proof(signed_freelancer_proof()));
        let pointer = format!("/{field}");
        let (policy, mut request, _) = policy_and_request_for(1, FREELANCER_TIMESHEET_EGRESS_PURPOSE_V1, &[&pointer]);
        request.payload[field] = serde_json::json!("private-activity-marker");
        assert_all_sends_denied(&proxy, &policy, request, EgressReasonCodeV1::InvalidPayload);
        assert!(transport.0.lock().unwrap().is_empty());
        store.close();
    }
}

#[test]
fn unrelated_general_delivery_keeps_its_existing_free_approval_path() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let transport = RecordingTransport::default();
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone());
    let (policy, request, artifact) = policy_and_request_for(1, "general-report-v1", &[]);
    let (_, approved) = approve_request(&proxy, &policy, request);
    proxy.send(&policy, approved, now(), 0).unwrap();
    assert_eq!(transport.0.lock().unwrap().as_slice(), &[artifact]);
    store.close();
}

#[test]
fn freelancer_revocation_import_waits_for_the_actual_send_and_blocks_the_next_packet() {
    use std::sync::mpsc;
    struct BlockingTransport { started: mpsc::Sender<()>, release: Mutex<mpsc::Receiver<()>>, count: Arc<Mutex<usize>> }
    impl EgressTransport for BlockingTransport {
        fn send(&self, _: &EgressDestinationV1, _: &EgressPurposeV1, _: &[u8]) -> Result<(), EgressReasonCodeV1> {
            *self.count.lock().unwrap() += 1;
            self.started.send(()).map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
            self.release.lock().unwrap().recv_timeout(std::time::Duration::from_secs(2)).map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?;
            Ok(())
        }
    }
    let proof = signed_freelancer_proof();
    let access = access_with_proof(proof.clone());
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let count = Arc::new(Mutex::new(0));
    let proxy = EgressProxy::with_transport(store.clone(), BlockingTransport { started: started_tx,
        release: Mutex::new(release_rx), count: count.clone() }).with_sync_access(access.clone());
    let (policy, request, _) = policy_and_request();
    let (preview_id, approved) = approve_request(&proxy, &policy, request);
    let approval_id = approved.approval_id().to_owned();
    let sender = proxy.clone();
    let send_policy = policy.clone();
    let send_thread = std::thread::spawn(move || sender.send(&send_policy, approved, now(), 0));
    started_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let (installed_tx, installed_rx) = mpsc::channel();
    let mut revoked = proof;
    revoked.revocations.as_mut().unwrap().sequence = 2;
    revoked.revocations.as_mut().unwrap().revoked_entitlement_ids = vec![revoked.entitlement.payload.claims.entitlement_id.clone()];
    sign_proof(&mut revoked);
    let import_thread = std::thread::spawn(move || {
        attempt_tx.send(()).unwrap();
        installed_tx.send(access.install(revoked, u64::try_from(now().timestamp()).unwrap())).unwrap();
    });
    attempt_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    let early = installed_rx.recv_timeout(std::time::Duration::from_millis(40));
    release_tx.send(()).unwrap();
    send_thread.join().unwrap().unwrap();
    assert!(early.is_err(), "revocation import completed while the actual packet was still being sent");
    assert!(matches!(installed_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap(), Err(aw_entitlements::RuntimeFeatureAccessErrorV1::Verification(aw_entitlements::EntitlementVerificationErrorV1::Revoked))));
    import_thread.join().unwrap();
    assert_eq!(proxy.send_approval(&policy, &preview_id, &approval_id, now(), 0), Err(EgressReasonCodeV1::ApprovalRequired));
    assert_eq!(*count.lock().unwrap(), 1);
    store.close();
}

#[test]
fn approved_timesheet_sends_only_exact_canonical_bytes_once() {
    let store = Datastore::new_in_memory(false);
    store.set_egress_kill_switch(false).unwrap();
    let transport = RecordingTransport::default();
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone()).with_sync_access(access_with_proof(signed_freelancer_proof()));
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
    assert_eq!(receipt.purpose_id, FREELANCER_TIMESHEET_EGRESS_PURPOSE_V1);
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
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone()).with_sync_access(access_with_proof(signed_freelancer_proof()));
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
    let proxy = EgressProxy::with_transport(store.clone(), transport.clone()).with_sync_access(access_with_proof(signed_freelancer_proof()));
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
    let locked_proxy = EgressProxy::with_transport(locked.clone(), locked_transport.clone()).with_sync_access(access_with_proof(signed_freelancer_proof()));
    let (policy, request, _) = policy_and_request();
    let denied = locked_proxy.preview(&policy, request, now, 0);
    assert_eq!(denied.outcome, EgressOutcomeV1::Deny);
    assert_eq!(denied.reason_codes, vec![EgressReasonCodeV1::KillSwitch]);
    assert!(locked_transport.0.lock().unwrap().is_empty());
    locked.close();
}
