#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::{
    Datastore, SyncApplyBatchV1, SyncDeviceIdentity, SyncHeadCommitV1, SyncKeyMaterial,
};
use aw_egress::{policy_bundle_signing_bytes, EgressProxy};
use aw_models::{
    EgressApprovalScopeV1, EgressPolicyBundleV1, EgressPolicyV1, EgressUserPolicyV1,
    SignedEgressPolicyBundleV1, SyncPolicyChoiceRequestV1, SyncPolicyDecisionV1,
};
use aw_server::endpoints::{
    choose_sync_policy, preview_sync_policy, EgressPolicyTrust, SyncPolicyFirewallReviewV1,
};
use aw_sync_e2ee::{create_policy_change, DeviceIdentityV1, SyncManifestV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};
use zeroize::Zeroizing;
const LOCAL: [u8; 16] = [0x71; 16];
const PEER: [u8; 16] = [0x81; 16];
const VAULT: [u8; 16] = [0x75; 16];
struct Fixture {
    store: Datastore,
    path: PathBuf,
    key: String,
    peer: DeviceIdentityV1,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "peak-policy-review-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = "c".repeat(64);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        store
            .create_sync_device_identity(&SyncDeviceIdentity::new(
                LOCAL,
                Zeroizing::new([0x72; 32]),
                Zeroizing::new([0x73; 32]),
            ))
            .unwrap();
        store
            .install_sync_key_material(&SyncKeyMaterial::new(
                Zeroizing::new([0x74; 32]),
                VAULT,
                1,
                [0x76; 24],
                [0x77; 48],
            ))
            .unwrap();
        let peer = DeviceIdentityV1::from_bytes(
            PEER,
            Zeroizing::new([0x82; 32]),
            Zeroizing::new([0x83; 32]),
        );
        let public = peer.public_identity();
        store
            .record_sync_pairing(
                None,
                [0x84; 16],
                PEER,
                URL_SAFE_NO_PAD
                    .decode(public.x25519_public_key)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                URL_SAFE_NO_PAD
                    .decode(public.ed25519_public_key)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                "2026-10-14T00:00:00Z".into(),
            )
            .unwrap();
        Self {
            store,
            path,
            key,
            peer,
        }
    }
    fn manifest(
        &self,
        field: &str,
        value: Value,
        revision: u64,
        counter: u64,
        parent: [u8; 32],
    ) -> SyncManifestV1 {
        let op = create_policy_change(
            PEER,
            counter,
            counter,
            BTreeMap::from([(field.to_owned(), value)]),
        )
        .unwrap();
        SyncManifestV1::new_signed(&self.peer, VAULT, 1, revision, parent, vec![op]).unwrap()
    }
    fn apply(
        &self,
        manifest: SyncManifestV1,
    ) -> Result<SyncHeadCommitV1, aw_datastore::DatastoreError> {
        self.store
            .apply_sync_operations(SyncApplyBatchV1 { manifest })
    }
    fn reopen(&mut self) {
        self.store.close();
        self.store =
            Datastore::open_encrypted(self.path.to_string_lossy().into_owned(), self.key.clone())
                .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.store.close();
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
    }
}
fn portable(value: Value) -> Value {
    json!({"schema_version":1,"present":true,"value":value})
}

fn signed_bundle(version: u64) -> (SignedEgressPolicyBundleV1, EgressPolicyTrust) {
    let vector: Value =
        serde_json::from_str(include_str!("../../test-vectors/privacy-firewall-v1.json")).unwrap();
    let policy: EgressPolicyV1 = serde_json::from_value(vector["policy"].clone()).unwrap();
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "policy-sync-test".into(),
        bundle: EgressPolicyBundleV1 {
            schema_version: 1,
            version,
            hard_deny_version: policy.hard_deny_version,
            destinations: policy.destinations,
            purposes: policy.purposes,
            organization_rules: policy.organization_rules,
        },
        signature: vec![],
    };
    sign(&mut signed);
    let pair = Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
    (
        signed,
        EgressPolicyTrust::from_release_keys(HashMap::from([(
            "policy-sync-test".into(),
            pair.public_key().as_ref().to_vec(),
        )])),
    )
}
fn sign(bundle: &mut SignedEgressPolicyBundleV1) {
    bundle.signature = Ed25519KeyPair::from_seed_unchecked(&[91; 32])
        .unwrap()
        .sign(&policy_bundle_signing_bytes(bundle).unwrap())
        .as_ref()
        .to_vec();
}
fn import(f: &Fixture, field: &str, value: Value) -> String {
    f.apply(f.manifest(field, portable(value), 1, 1, [0; 32]))
        .unwrap();
    f.store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .candidate_id
        .clone()
}
fn request(preview: &aw_models::SyncPolicyPreviewV1) -> SyncPolicyChoiceRequestV1 {
    SyncPolicyChoiceRequestV1 {
        schema_version: 1,
        candidate_id: preview.candidate.candidate_id.clone(),
        expected_review_sha256: preview.expected_review_sha256.clone(),
        decision: SyncPolicyDecisionV1::AcceptRemote,
    }
}
fn empty_user() -> EgressUserPolicyV1 {
    EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: vec![],
        safe_zone_patterns: vec![],
        after_hours: None,
    }
}
fn user() -> EgressUserPolicyV1 {
    serde_json::from_value(json!({"schema_version":1,"user_rules":[{"pattern":{"kind":"keyword","value":"banking"},"action":"deny"}],"safe_zone_patterns":[],"after_hours":null})).unwrap()
}
fn approval(f: &Fixture) -> String {
    f.store.set_egress_kill_switch(false).unwrap();
    f.store
        .create_egress_approval(
            "sync-relay",
            "sync",
            "test",
            3,
            EgressApprovalScopeV1::Once,
            [3; 32],
            Some(Utc::now() + Duration::minutes(5)),
            Utc::now(),
        )
        .unwrap()
}
#[test]
fn signed_peer_choice_uses_release_verification_and_durable_atomic_activation() {
    let mut f = Fixture::new();
    let (bundle, trust) = signed_bundle(3);
    f.store.begin_sync_baseline().unwrap();
    let id = import(&f, "egress.signed_bundle", json!(bundle));
    assert!(f.store.get_egress_policy_state().unwrap().is_none());
    let approved = approval(&f);
    let before = f
        .store
        .list_sync_operations(LOCAL, 1, 0, 256)
        .unwrap()
        .len();
    let proxy = EgressProxy::new(f.store.clone());
    let review = preview_sync_policy(&f.store, &trust, &proxy, &id).unwrap();
    assert!(
        choose_sync_policy(
            &f.store,
            &trust,
            &proxy,
            request(&review.policy),
            review.firewall
        )
        .unwrap()
        .applied
    );
    assert_eq!(
        f.store.get_egress_policy_state().unwrap(),
        Some((bundle.clone(), empty_user()))
    );
    assert_eq!(
        f.store
            .list_sync_operations(LOCAL, 1, 0, 256)
            .unwrap()
            .len(),
        before + 1
    );
    assert!(f
        .store
        .get_egress_approval(&approved, Utc::now())
        .unwrap()
        .is_none());
    f.reopen();
    assert_eq!(
        f.store.get_egress_policy_state().unwrap(),
        Some((bundle, empty_user()))
    );
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
}
#[test]
fn untrusted_and_tampered_signed_candidates_stay_pending_without_mutation() {
    for case in 0..3 {
        let f = Fixture::new();
        let (mut bundle, mut trust) = signed_bundle(3);
        match case {
            0 => trust = EgressPolicyTrust::default(),
            1 => bundle.signer_key_id = "unknown".into(),
            _ => {
                bundle.bundle.destinations[0].https_origin = Some("https://tampered.example".into())
            }
        }
        let id = import(&f, "egress.signed_bundle", json!(bundle));
        let approved = approval(&f);
        let before = f.store.list_sync_operations(LOCAL, 1, 0, 256).unwrap();
        let proxy = EgressProxy::new(f.store.clone());
        assert!(preview_sync_policy(&f.store, &trust, &proxy, &id).is_err());
        let raw = f.store.preview_sync_policy_candidate(&id).unwrap();
        let (valid, valid_trust) = signed_bundle(3);
        let other = Fixture::new();
        let valid_id = import(&other, "egress.signed_bundle", json!(valid));
        let diff = preview_sync_policy(
            &other.store,
            &valid_trust,
            &EgressProxy::new(other.store.clone()),
            &valid_id,
        )
        .unwrap()
        .firewall;
        assert!(choose_sync_policy(&f.store, &trust, &proxy, request(&raw), diff).is_err());
        assert!(f.store.get_egress_policy_state().unwrap().is_none());
        assert_eq!(
            f.store.list_sync_operations(LOCAL, 1, 0, 256).unwrap(),
            before
        );
        assert!(f
            .store
            .get_egress_approval(&approved, Utc::now())
            .unwrap()
            .is_some());
        assert_eq!(
            f.store
                .list_sync_policy_candidates(None, 256)
                .unwrap()
                .candidates
                .len(),
            1
        );
    }
}
#[test]
fn signed_choice_rejects_replay_wrong_diff_and_changed_local_user() {
    for case in 0..3 {
        let f = Fixture::new();
        let (current, trust) = signed_bundle(3);
        f.store
            .store_egress_policy_state(&current, &empty_user())
            .unwrap();
        let (mut candidate, _) = signed_bundle(if case == 0 { 3 } else { 4 });
        candidate.bundle.purposes[0].retention_disclosure = "changed disclosure".into();
        sign(&mut candidate);
        let id = import(&f, "egress.signed_bundle", json!(candidate));
        let proxy = EgressProxy::new(f.store.clone());
        if case == 0 {
            assert!(preview_sync_policy(&f.store, &trust, &proxy, &id).is_err());
            continue;
        }
        let mut review = preview_sync_policy(&f.store, &trust, &proxy, &id).unwrap();
        if case == 1 {
            if let Some(SyncPolicyFirewallReviewV1::SignedBundle { diff }) = &mut review.firewall {
                diff.to_version += 1;
            }
        } else {
            f.store.store_egress_user_policy(&user()).unwrap();
        }
        let before = f.store.get_egress_policy_state().unwrap();
        assert!(choose_sync_policy(
            &f.store,
            &trust,
            &proxy,
            request(&review.policy),
            review.firewall
        )
        .is_err());
        assert_eq!(f.store.get_egress_policy_state().unwrap(), before);
        assert_eq!(
            f.store
                .list_sync_policy_candidates(None, 256)
                .unwrap()
                .candidates
                .len(),
            1
        );
    }
}
#[test]
fn local_user_choice_is_free_without_destination_bundle_and_preview_is_single_use() {
    let f = Fixture::new();
    let id = import(&f, "egress.user_policy", json!(user()));
    let proxy = EgressProxy::new(f.store.clone());
    let trust = EgressPolicyTrust::default();
    let review = preview_sync_policy(&f.store, &trust, &proxy, &id).unwrap();
    let (token, base) = match review.firewall.as_ref().unwrap() {
        SyncPolicyFirewallReviewV1::UserPolicy { preview_id, .. } => (
            preview_id.clone(),
            EgressPolicyV1 {
                schema_version: 1,
                version: 0,
                hard_deny_version: 0,
                destinations: vec![],
                purposes: vec![],
                organization_rules: vec![],
                user_rules: vec![],
                safe_zone_patterns: vec![],
                after_hours: None,
            },
        ),
        _ => panic!(),
    };
    assert!(
        choose_sync_policy(
            &f.store,
            &trust,
            &proxy,
            request(&review.policy),
            review.firewall
        )
        .unwrap()
        .applied
    );
    assert_eq!(f.store.get_egress_user_policy().unwrap(), user());
    assert!(f.store.get_egress_policy_state().unwrap().is_none());
    assert!(proxy.accept_user_policy(&token, &base, Utc::now()).is_err());
}
#[test]
fn expired_user_preview_and_changed_bundle_cannot_authorize_choice() {
    for expired in [true, false] {
        let f = Fixture::new();
        let id = import(&f, "egress.user_policy", json!(user()));
        let proxy = EgressProxy::new(f.store.clone());
        let (bundle, trust) = signed_bundle(3);
        let mut review = preview_sync_policy(&f.store, &trust, &proxy, &id).unwrap();
        if expired {
            let base = EgressPolicyV1 {
                schema_version: 1,
                version: 0,
                hard_deny_version: 0,
                destinations: vec![],
                purposes: vec![],
                organization_rules: vec![],
                user_rules: vec![],
                safe_zone_patterns: vec![],
                after_hours: None,
            };
            let old = proxy
                .preview_user_policy(
                    &base,
                    &empty_user(),
                    &user(),
                    Utc::now() - Duration::minutes(5),
                )
                .unwrap();
            review.firewall = Some(SyncPolicyFirewallReviewV1::UserPolicy {
                preview_id: old.preview_id,
                diff: old.diff,
            });
        } else {
            f.store
                .store_egress_policy_state(&bundle, &empty_user())
                .unwrap();
        }
        assert!(choose_sync_policy(
            &f.store,
            &trust,
            &proxy,
            request(&review.policy),
            review.firewall
        )
        .is_err());
        assert_eq!(f.store.get_egress_user_policy().unwrap(), empty_user());
        assert_eq!(
            f.store
                .list_sync_policy_candidates(None, 256)
                .unwrap()
                .candidates
                .len(),
            1
        );
    }
}
#[test]
fn firewall_choice_write_and_commit_failures_restore_policy_journal_and_approvals() {
    for commit in [false, true] {
        let mut f = Fixture::new();
        let (old, trust) = signed_bundle(3);
        let (next, _) = signed_bundle(4);
        f.store.store_egress_policy_state(&old, &user()).unwrap();
        f.store.begin_sync_baseline().unwrap();
        let id = import(&f, "egress.signed_bundle", json!(next));
        let before = f.store.list_sync_operations(LOCAL, 1, 0, 256).unwrap();
        f.store.close();
        let conn = rusqlite::Connection::open(&f.path).unwrap();
        conn.pragma_update(None, "key", f.key.as_str()).unwrap();
        if commit {
            conn.execute_batch("CREATE TABLE review_parent(id INTEGER PRIMARY KEY);CREATE TABLE review_child(parent_id INTEGER NOT NULL REFERENCES review_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_review_commit AFTER INSERT ON key_value WHEN NEW.key LIKE 'peakactivity.sync_policy_decisions%' BEGIN INSERT INTO review_child(parent_id) VALUES(1); END;").unwrap();
        } else {
            conn.execute_batch("CREATE TRIGGER fail_review_decision BEFORE INSERT ON key_value WHEN NEW.key LIKE 'peakactivity.sync_policy_decisions%' BEGIN SELECT RAISE(ABORT,'synthetic decision failure'); END;").unwrap();
        }
        drop(conn);
        f.reopen();
        let approved = approval(&f);
        let proxy = EgressProxy::new(f.store.clone());
        let review = preview_sync_policy(&f.store, &trust, &proxy, &id).unwrap();
        assert!(choose_sync_policy(
            &f.store,
            &trust,
            &proxy,
            request(&review.policy),
            review.firewall
        )
        .is_err());
        assert!(f
            .store
            .get_egress_approval(&approved, Utc::now())
            .unwrap()
            .is_some());
        f.reopen();
        assert_eq!(
            f.store.get_egress_policy_state().unwrap(),
            Some((old, user()))
        );
        assert_eq!(
            f.store.list_sync_operations(LOCAL, 1, 0, 256).unwrap(),
            before
        );
        assert_eq!(
            f.store
                .list_sync_policy_candidates(None, 256)
                .unwrap()
                .candidates
                .len(),
            1
        );
    }
}
