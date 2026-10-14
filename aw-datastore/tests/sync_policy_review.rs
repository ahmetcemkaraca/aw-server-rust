#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::{
    Datastore, SyncApplyBatchV1, SyncDeviceIdentity, SyncHeadCommitV1, SyncKeyMaterial,
};
use aw_models::{SyncPolicyChoiceRequestV1, SyncPolicyDecisionV1};
use aw_sync_e2ee::{create_policy_change, DeviceIdentityV1, SyncManifestV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf};
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

#[test]
fn authenticated_portable_import_is_durable_without_overwriting_active_settings() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    let manifest = f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]);
    assert_eq!(
        f.apply(manifest.clone()).unwrap(),
        SyncHeadCommitV1::Advanced
    );
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert_eq!(
        f.store.list_sync_operations(PEER, 1, 0, 32).unwrap().len(),
        1
    );
    f.reopen();
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert_eq!(f.apply(manifest).unwrap(), SyncHeadCommitV1::Duplicate);
}

#[test]
fn authenticated_policy_import_rejects_unsupported_scope_without_head_or_counter() {
    let f = Fixture::new();
    let manifest = f.manifest("capture.recording", portable(json!(true)), 1, 1, [0; 32]);
    assert!(f.apply(manifest).is_err());
    assert!(f
        .store
        .load_sync_manifest_head(VAULT, 1, PEER)
        .unwrap()
        .is_none());
    assert!(f
        .store
        .list_sync_operations(PEER, 1, 0, 32)
        .unwrap()
        .is_empty());
}

#[test]
fn authenticated_policy_import_rejects_malformed_version_type_and_wrapper_atomically() {
    for value in [
        json!({"schema_version":2,"present":true,"value":"light"}),
        portable(json!("neon")),
        json!([1, true, "light"]),
        json!({"schema_version":1,"present":true,"value":"light","trusted":true}),
    ] {
        let f = Fixture::new();
        assert!(f
            .apply(f.manifest("settings.theme", value, 1, 1, [0; 32]))
            .is_err());
        assert!(f
            .store
            .load_sync_manifest_head(VAULT, 1, PEER)
            .unwrap()
            .is_none());
        assert!(f
            .store
            .list_sync_operations(PEER, 1, 0, 32)
            .unwrap()
            .is_empty());
    }
}

fn choice(
    preview: &aw_models::SyncPolicyPreviewV1,
    decision: SyncPolicyDecisionV1,
) -> SyncPolicyChoiceRequestV1 {
    SyncPolicyChoiceRequestV1 {
        schema_version: 1,
        candidate_id: preview.candidate.candidate_id.clone(),
        expected_review_sha256: preview.expected_review_sha256.clone(),
        decision,
    }
}

fn recovery_state(f: &Fixture) -> aw_datastore::SyncRecoveryStateV1 {
    let mut state=f.store.export_sync_recovery_state(1).unwrap();
    let public=DeviceIdentityV1::from_bytes(LOCAL,Zeroizing::new([0x72;32]),Zeroizing::new([0x73;32])).public_identity();
    state.trusted_devices.push(aw_datastore::SyncRecoveryTrustedDeviceV1 {device_id:LOCAL,x25519_public_key:URL_SAFE_NO_PAD.decode(public.x25519_public_key).unwrap().try_into().unwrap(),ed25519_public_key:URL_SAFE_NO_PAD.decode(public.ed25519_public_key).unwrap().try_into().unwrap(),paired_at:"2026-10-14T00:00:00Z".into()});
    state
}
fn recovery_snapshot() -> aw_datastore::SyncSnapshotV1 {
    aw_datastore::SyncSnapshotV1::new([0x91;16],vec![aw_models::SyncEnvelopeV1 {schema_version:1,object_id:URL_SAFE_NO_PAD.encode([0x92;16]),vault_id:URL_SAFE_NO_PAD.encode(VAULT),key_epoch:1,nonce:URL_SAFE_NO_PAD.encode([0x93;24]),ciphertext:URL_SAFE_NO_PAD.encode([0x94;16])}])
}
fn recovery_identity() -> SyncDeviceIdentity { SyncDeviceIdentity::new([0x95;16],Zeroizing::new([0x96;32]),Zeroizing::new([0x97;32])) }
fn recovery_target() -> Datastore {
    let store=Datastore::open_encrypted(":memory:".into(),"e".repeat(64)).unwrap();
    store.enable_capture_policy().unwrap();store.pause_capture().unwrap();store
}

#[test]
fn recovery_preserves_valid_keep_only_for_matching_target_and_prebaseline_peer_history() {
    let f=Fixture::new();f.store.set_key_value("settings.theme","\"dark\"").unwrap();
    f.apply(f.manifest("settings.theme",portable(json!("light")),1,1,[0;32])).unwrap();
    let candidate=f.store.list_sync_policy_candidates(None,256).unwrap().candidates.remove(0);
    let preview=f.store.preview_sync_policy_candidate(&candidate.candidate_id).unwrap();
    f.store.choose_sync_policy(choice(&preview,SyncPolicyDecisionV1::KeepLocal)).unwrap();
    let state=recovery_state(&f);assert!(!state.baseline_complete);assert_eq!(state.operations.len(),1);
    for (value,expected) in [("dark",0),("auto",1)] {
        let target=recovery_target();target.set_key_value("settings.theme",&json!(value).to_string()).unwrap();
        let summary=target.preview_sync_recovery_policy(state.clone(),VAULT,1,[0x91;16],false).unwrap();assert_eq!(summary.conflict_count,expected);
        target.restore_sync_recovery_data(aw_models::BucketsExport {buckets:Default::default()},f.store.load_sync_key_material().unwrap().unwrap(),recovery_snapshot(),state.clone(),recovery_identity()).unwrap();
        assert_eq!(target.get_key_value("settings.theme").unwrap(),json!(value).to_string());
        let candidates=target.list_sync_policy_candidates(None,256).unwrap().candidates;
        assert_eq!(candidates.iter().map(|candidate|candidate.field.as_str()).collect::<std::collections::BTreeSet<_>>().len(),expected);
        if expected==0 { assert!(candidates.is_empty()); }
        assert!(!target.capture_policy().unwrap().recording);assert!(!target.sync_enabled().unwrap());assert!(target.sync_egress_consent().unwrap().is_none());
        assert_eq!(target.list_sync_operations(PEER,1,0,256).unwrap().len(),1);
        target.close();
    }
}

#[test]
fn recovery_category_decision_reopens_when_only_category_companion_changes() {
    let f=Fixture::new();f.store.set_key_value("settings.active_set_ids","[]").unwrap();
    f.apply(f.manifest("settings.active_set_ids",portable(json!(["remote"])),1,1,[0;32])).unwrap();
    let candidate=f.store.list_sync_policy_candidates(None,256).unwrap().candidates.remove(0);
    let preview=f.store.preview_sync_policy_candidate(&candidate.candidate_id).unwrap();f.store.choose_sync_policy(choice(&preview,SyncPolicyDecisionV1::KeepLocal)).unwrap();
    let state=recovery_state(&f);
    for changed in [false,true] {
        let target=recovery_target();target.set_key_value("settings.active_set_ids","[]").unwrap();
        if changed {target.set_key_value("settings.category_sets","[]").unwrap();}
        let summary=target.preview_sync_recovery_policy(state.clone(),VAULT,1,[0x91;16],false).unwrap();
        target.restore_sync_recovery_data(aw_models::BucketsExport {buckets:Default::default()},f.store.load_sync_key_material().unwrap().unwrap(),recovery_snapshot(),state.clone(),recovery_identity()).unwrap();
        let fields=target.list_sync_policy_candidates(None,256).unwrap().candidates.into_iter().map(|item|item.field).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(fields.contains("settings.active_set_ids"),changed);assert_eq!(fields.len(),summary.conflict_count);assert_eq!(target.get_key_value("settings.active_set_ids").unwrap(),"[]");target.close();
    }
}

#[test]
fn recovery_signed_bundle_keep_reopens_when_only_user_policy_companion_changes() {
    let f=Fixture::new();
    let bundle=json!({"schema_version":1,"signer_key_id":"synthetic-root","signature":vec![0u8;64],"bundle":{"schema_version":1,"version":1,"hard_deny_version":1,"destinations":[],"purposes":[],"organization_rules":[]}});
    f.apply(f.manifest("egress.signed_bundle",portable(bundle),1,1,[0;32])).unwrap();
    let candidate=f.store.list_sync_policy_candidates(None,256).unwrap().candidates.remove(0);
    let preview=f.store.preview_sync_policy_candidate(&candidate.candidate_id).unwrap();f.store.choose_sync_policy(choice(&preview,SyncPolicyDecisionV1::KeepLocal)).unwrap();
    let state=recovery_state(&f);
    for changed in [false,true] {
        let target=recovery_target();
        if changed {target.store_egress_user_policy(&serde_json::from_value(json!({"schema_version":1,"user_rules":[],"safe_zone_patterns":[{"kind":"application","value":"TargetApp"}],"after_hours":null})).unwrap()).unwrap();}
        let summary=target.preview_sync_recovery_policy(state.clone(),VAULT,1,[0x91;16],false).unwrap();
        target.restore_sync_recovery_data(aw_models::BucketsExport {buckets:Default::default()},f.store.load_sync_key_material().unwrap().unwrap(),recovery_snapshot(),state.clone(),recovery_identity()).unwrap();
        let fields=target.list_sync_policy_candidates(None,256).unwrap().candidates.into_iter().map(|item|item.field).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(fields.contains("egress.signed_bundle"),changed);assert_eq!(fields.len(),summary.conflict_count);assert!(target.get_egress_policy_state().unwrap().is_none());assert!(!target.sync_enabled().unwrap());target.close();
    }
}

#[test]
fn recovery_rejects_unknown_decision_reference_and_changed_target_without_any_restore_write() {
    let f=Fixture::new();f.store.set_key_value("settings.theme","\"dark\"").unwrap();
    f.apply(f.manifest("settings.theme",portable(json!("light")),1,1,[0;32])).unwrap();
    let candidate=f.store.list_sync_policy_candidates(None,256).unwrap().candidates.remove(0);
    let preview=f.store.preview_sync_policy_candidate(&candidate.candidate_id).unwrap();
    f.store.choose_sync_policy(choice(&preview,SyncPolicyDecisionV1::KeepLocal)).unwrap();
    let state=recovery_state(&f);let target=recovery_target();
    let summary=target.preview_sync_recovery_policy(state.clone(),VAULT,1,[0x91;16],false).unwrap();
    target.set_key_value("settings.theme","\"auto\"").unwrap();
    assert!(target.restore_sync_recovery_data_with_policy_target(aw_models::BucketsExport {buckets:Default::default()},f.store.load_sync_key_material().unwrap().unwrap(),recovery_snapshot(),state.clone(),recovery_identity(),Some(summary.target_binding_sha256)).is_err());
    let mut bad=state;bad.policy.as_mut().unwrap().decisions[0].candidate_ids=vec!["a".repeat(64)];
    assert!(target.preview_sync_recovery_policy(bad.clone(),VAULT,1,[0x91;16],false).is_err());
    assert!(target.restore_sync_recovery_data(aw_models::BucketsExport {buckets:Default::default()},f.store.load_sync_key_material().unwrap().unwrap(),recovery_snapshot(),bad,recovery_identity()).is_err());
    assert!(target.load_sync_key_material().unwrap().is_none());assert!(target.load_sync_snapshot().unwrap().is_none());assert_eq!(target.get_key_value("settings.theme").unwrap(),"\"auto\"");
    target.close();
}

#[test]
fn restored_pending_snapshot_values_survive_next_export_without_fabricated_operations_or_generic_kv_access() {
    let f=Fixture::new();f.store.set_key_value("settings.theme","\"dark\"").unwrap();
    let target=recovery_target();target.restore_sync_recovery_data(aw_models::BucketsExport {buckets:Default::default()},f.store.load_sync_key_material().unwrap().unwrap(),recovery_snapshot(),recovery_state(&f),recovery_identity()).unwrap();
    assert!(target.list_sync_operations([0x95;16],1,0,256).unwrap().is_empty());
    let state=target.export_sync_recovery_state(1).unwrap();assert_eq!(state.policy.as_ref().unwrap().pending_recovery.len(),21);
    assert!(target.get_key_values("peakactivity.sync_policy_decisions%").unwrap().is_empty());
    let next=recovery_target();let summary=next.preview_sync_recovery_policy(state,VAULT,1,[0x98;16],false).unwrap();assert_eq!(summary.conflict_count,1);
    let candidate=target.list_sync_policy_candidates(None,256).unwrap().candidates.remove(0);
    let preview=target.preview_sync_policy_candidate(&candidate.candidate_id).unwrap();
    target.choose_sync_policy(choice(&preview,SyncPolicyDecisionV1::KeepLocal)).unwrap();
    assert!(target.list_sync_policy_candidates(None,256).unwrap().candidates.is_empty());
    assert_eq!(target.export_sync_recovery_state(1).unwrap().policy.unwrap().decisions.len(),1);
    target.close();next.close();
}

#[test]
fn recovery_snapshot_candidate_failure_rolls_back_keys_snapshot_identity_and_settings_at_actual_commit() {
    let f=Fixture::new();f.store.set_key_value("settings.theme","\"dark\"").unwrap();let state=recovery_state(&f);
    for deferred in [false,true] {
        let path=f.path.with_extension(if deferred {"commit-target.db"} else {"trigger-target.db"});let key="f".repeat(64);
        let store=Datastore::open_encrypted(path.to_string_lossy().into_owned(),key.clone()).unwrap();store.enable_capture_policy().unwrap();store.pause_capture().unwrap();store.set_key_value("settings.theme","\"light\"").unwrap();
        let identity=SyncDeviceIdentity::new([0xa1;16],Zeroizing::new([0xa2;32]),Zeroizing::new([0xa3;32]));store.create_sync_device_identity(&identity).unwrap();store.close();
        let conn=rusqlite::Connection::open(&path).unwrap();conn.pragma_update(None,"key",key.as_str()).unwrap();
        if deferred {conn.execute_batch("CREATE TABLE recovery_parent(id INTEGER PRIMARY KEY);CREATE TABLE recovery_child(parent_id INTEGER NOT NULL REFERENCES recovery_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER fail_recovery_commit AFTER INSERT ON key_value WHEN NEW.key GLOB 'peakactivity.sync_policy_decisions.recovery.*' BEGIN INSERT INTO recovery_child(parent_id) VALUES(1); END;").unwrap();}
        else {conn.execute_batch("CREATE TRIGGER fail_recovery_stage BEFORE INSERT ON key_value WHEN NEW.key GLOB 'peakactivity.sync_policy_decisions.recovery.*' BEGIN SELECT RAISE(ABORT,'synthetic recovery stage failure'); END;").unwrap();}
        drop(conn);let store=Datastore::open_encrypted(path.to_string_lossy().into_owned(),key.clone()).unwrap();
        assert!(store.restore_sync_recovery_data(aw_models::BucketsExport {buckets:Default::default()},f.store.load_sync_key_material().unwrap().unwrap(),recovery_snapshot(),state.clone(),recovery_identity()).is_err());store.close();
        let store=Datastore::open_encrypted(path.to_string_lossy().into_owned(),key).unwrap();assert!(store.load_sync_key_material().unwrap().is_none());assert!(store.load_sync_snapshot().unwrap().is_none());assert_eq!(store.load_sync_device_identity().unwrap().unwrap().device_id(),identity.device_id());assert_eq!(store.get_key_value("settings.theme").unwrap(),"\"light\"");assert!(store.get_buckets().unwrap().is_empty());store.close();
        let conn=rusqlite::Connection::open(&path).unwrap();conn.pragma_update(None,"key","f".repeat(64)).unwrap();assert_eq!(conn.query_row("SELECT COUNT(*) FROM key_value WHERE key GLOB 'peakactivity.sync_policy_decisions*'",[],|row|row.get::<_,i64>(0)).unwrap(),0);drop(conn);let _=std::fs::remove_file(&path);
    }
}

#[test]
fn pending_policy_keep_local_survives_reopen_and_replay_but_new_change_reopens() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    let first = f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]);
    f.apply(first.clone()).unwrap();
    let pending = f.store.list_sync_policy_candidates(None, 256).unwrap();
    assert_eq!(pending.candidates.len(), 1);
    let preview = f
        .store
        .preview_sync_policy_candidate(&pending.candidates[0].candidate_id)
        .unwrap();
    assert_eq!(preview.current.value, json!("dark"));
    assert_eq!(preview.proposed.value, json!("light"));
    f.store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::KeepLocal))
        .unwrap();
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
    f.reopen();
    f.apply(first.clone()).unwrap();
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
    let parent = URL_SAFE_NO_PAD
        .decode(first.head_hash)
        .unwrap()
        .try_into()
        .unwrap();
    f.apply(f.manifest("settings.theme", portable(json!("auto")), 2, 2, parent))
        .unwrap();
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
}

#[test]
fn recovery_policy_export_binds_reviewed_current_values_and_rejects_ambiguous_or_invalid_records() {
    let f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    assert!(f.store.begin_sync_baseline().unwrap().complete);
    let first = f.manifest("settings.theme", portable(json!("light")), 1, 1, [0;32]);
    f.apply(first).unwrap();
    let candidate = f.store.list_sync_policy_candidates(None,256).unwrap().candidates.remove(0);
    let preview = f.store.preview_sync_policy_candidate(&candidate.candidate_id).unwrap();
    f.store.choose_sync_policy(choice(&preview,SyncPolicyDecisionV1::KeepLocal)).unwrap();
    let exported = f.store.export_sync_recovery_state(1).unwrap();
    let policy = exported.policy.unwrap();
    assert_eq!(policy.decisions.len(),1);
    assert_eq!(policy.decisions[0].candidate_ids,vec![candidate.candidate_id]);
    assert_eq!(policy.decisions[0].field,"settings.theme");
    aw_datastore::validate_sync_recovery_policy_v1(&policy).unwrap();
    let json = serde_json::to_string(&policy).unwrap();
    for bad in [json.replace("\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1"),
        json.replace("\"schema_version\":1", "\"trusted\":true,\"schema_version\":1"),
        serde_json::to_string(&json!([1,[],[]])).unwrap()] {
        assert!(serde_json::from_str::<aw_models::SyncRecoveryPolicyV1>(&bad).is_err());
    }
    let mut duplicate = policy.clone(); duplicate.active_values[0] = duplicate.active_values[1].clone();
    assert!(aw_datastore::validate_sync_recovery_policy_v1(&duplicate).is_err());
    let mut tampered = policy.clone(); tampered.decisions[0].active_binding_sha256 = "a".repeat(64);
    assert!(aw_datastore::validate_sync_recovery_policy_v1(&tampered).is_err());
    f.store.set_key_value("settings.theme", "\"auto\"").unwrap();
    let newer = f.store.export_sync_recovery_state(1).unwrap().policy.unwrap();
    assert_ne!(newer.decisions[0].active_binding_sha256, policy.decisions[0].active_binding_sha256);
}

#[test]
fn pending_policy_accept_changes_setting_and_decision_atomically_and_journals_once() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.store.begin_sync_baseline().unwrap();
    let local_before = f.store.list_sync_operations(LOCAL, 1, 0, 256).unwrap();
    f.apply(f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]))
        .unwrap();
    let candidate = f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .clone();
    let preview = f
        .store
        .preview_sync_policy_candidate(&candidate.candidate_id)
        .unwrap();
    f.store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .unwrap();
    assert_eq!(
        f.store.get_key_value("settings.theme").unwrap(),
        "\"light\""
    );
    assert_eq!(
        f.store
            .list_sync_operations(LOCAL, 1, 0, 256)
            .unwrap()
            .len(),
        local_before.len() + 1
    );
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
    f.reopen();
    assert_eq!(
        f.store.get_key_value("settings.theme").unwrap(),
        "\"light\""
    );
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
}

#[test]
fn pending_policy_review_rejects_local_and_remote_changes_after_preview() {
    let f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    let first = f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]);
    f.apply(first.clone()).unwrap();
    let candidate = f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .clone();
    let old = f
        .store
        .preview_sync_policy_candidate(&candidate.candidate_id)
        .unwrap();
    f.store.set_key_value("settings.theme", "\"auto\"").unwrap();
    assert!(f
        .store
        .choose_sync_policy(choice(&old, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"auto\"");
    let old = f
        .store
        .preview_sync_policy_candidate(&candidate.candidate_id)
        .unwrap();
    let parent = URL_SAFE_NO_PAD
        .decode(first.head_hash)
        .unwrap()
        .try_into()
        .unwrap();
    f.apply(f.manifest("settings.theme", portable(json!("dark")), 2, 2, parent))
        .unwrap();
    assert!(f
        .store
        .choose_sync_policy(choice(&old, SyncPolicyDecisionV1::KeepLocal))
        .is_err());
}

#[test]
fn pending_policy_decision_metadata_has_no_generic_kv_bypass() {
    let f = Fixture::new();
    let key = "peakactivity.sync_policy_decisions.v1";
    assert!(f.store.get_key_value(key).is_err());
    assert!(f.store.set_key_value(key, "{}").is_err());
    assert!(f.store.delete_key_value(key).is_err());
    assert!(f
        .store
        .compare_and_set_key_value(key, None, Some("{}"))
        .is_err());
}

#[test]
fn pending_policy_egress_acceptance_requires_a_nonserializable_activation_gate() {
    let f = Fixture::new();
    let policy = json!({"schema_version":1,"user_rules":[],"safe_zone_patterns":[],"after_hours":{"weekdays":[1],"start_minute":60,"end_minute":120}});
    f.apply(f.manifest("egress.user_policy", portable(policy), 1, 1, [0; 32]))
        .unwrap();
    let candidate = f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .clone();
    let preview = f
        .store
        .preview_sync_policy_candidate(&candidate.candidate_id)
        .unwrap();
    assert!(f
        .store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    assert_eq!(f.store.get_egress_user_policy().unwrap().after_hours, None);
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
}

#[test]
fn pending_policy_decision_write_failure_rolls_back_active_setting_and_local_journal() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.store.begin_sync_baseline().unwrap();
    f.apply(f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]))
        .unwrap();
    let before = f.store.list_sync_operations(LOCAL, 1, 0, 256).unwrap();
    f.store.close();
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    conn.pragma_update(None, "key", f.key.as_str()).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_review_decision BEFORE INSERT ON key_value WHEN NEW.key LIKE 'peakactivity.sync_policy_decisions%' BEGIN SELECT RAISE(ABORT,'synthetic decision failure'); END;").unwrap();
    drop(conn);
    f.reopen();
    let candidate = f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .clone();
    let preview = f
        .store
        .preview_sync_policy_candidate(&candidate.candidate_id)
        .unwrap();
    assert!(f
        .store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
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

#[test]
fn pending_policy_actual_commit_failure_keeps_decision_and_settings_pending() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.apply(f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]))
        .unwrap();
    f.store.close();
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    conn.pragma_update(None, "key", f.key.as_str()).unwrap();
    conn.execute_batch("CREATE TABLE review_parent(id INTEGER PRIMARY KEY);CREATE TABLE review_child(parent_id INTEGER NOT NULL REFERENCES review_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER fail_review_commit AFTER INSERT ON key_value WHEN NEW.key LIKE 'peakactivity.sync_policy_decisions%' BEGIN INSERT INTO review_child(parent_id) VALUES(1); END;").unwrap();
    drop(conn);
    f.reopen();
    let candidate = f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .clone();
    let preview = f
        .store
        .preview_sync_policy_candidate(&candidate.candidate_id)
        .unwrap();
    assert!(f
        .store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
    f.reopen();
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
}

#[test]
fn pending_policy_unrelated_scope_does_not_stale_review_and_metadata_pages_are_stable() {
    let f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    let first = f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]);
    f.apply(first.clone()).unwrap();
    let page = f.store.list_sync_policy_candidates(None, 1).unwrap();
    let preview = f
        .store
        .preview_sync_policy_candidate(&page.candidates[0].candidate_id)
        .unwrap();
    let parent = URL_SAFE_NO_PAD
        .decode(first.head_hash)
        .unwrap()
        .try_into()
        .unwrap();
    let second = f.manifest(
        "settings.startOfDay",
        portable(json!("04:00")),
        2,
        2,
        parent,
    );
    f.apply(second).unwrap();
    let page = f.store.list_sync_policy_candidates(None, 1).unwrap();
    let cursor = page.next_cursor.as_ref().unwrap();
    let next = f
        .store
        .list_sync_policy_candidates(Some(cursor), 1)
        .unwrap();
    assert_eq!(next.candidates.len(), 1);
    assert_ne!(
        page.candidates[0].candidate_id,
        next.candidates[0].candidate_id
    );
    f.store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::KeepLocal))
        .unwrap();
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
}

#[test]
fn pending_policy_gate_denial_never_resolves_or_activates_egress() {
    let f = Fixture::new();
    let policy = json!({"schema_version":1,"user_rules":[],"safe_zone_patterns":[],"after_hours":{"weekdays":[1],"start_minute":60,"end_minute":120}});
    f.apply(f.manifest("egress.user_policy", portable(policy), 1, 1, [0; 32]))
        .unwrap();
    let candidate = f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates[0]
        .clone();
    let preview = f
        .store
        .preview_sync_policy_candidate(&candidate.candidate_id)
        .unwrap();
    let gate = aw_datastore::SyncPolicyActivationGateV1::new(|_| {
        Err(aw_datastore::DatastoreError::InvalidImport(
            "synthetic denied activation".into(),
        ))
    });
    assert!(f
        .store
        .choose_sync_policy_with_activation(
            choice(&preview, SyncPolicyDecisionV1::AcceptRemote),
            Some(gate)
        )
        .is_err());
    assert_eq!(f.store.get_egress_user_policy().unwrap().after_hours, None);
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        1
    );
}

fn window_bucket() -> aw_models::Bucket {
    aw_models::Bucket {
        bid: None,
        id: "aw-watcher-window_review".into(),
        _type: "currentwindow".into(),
        client: "test".into(),
        hostname: "test".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: None,
        last_updated: None,
    }
}
fn window_event() -> aw_models::Event {
    aw_models::Event::new(
        chrono::Utc::now(),
        chrono::Duration::zero(),
        json!({"app":"Editor","title":"private title"})
            .as_object()
            .unwrap()
            .clone(),
    )
}
fn review_first(f: &Fixture) -> aw_models::SyncPolicyPreviewV1 {
    let list = f.store.list_sync_policy_candidates(None, 256).unwrap();
    f.store
        .preview_sync_policy_candidate(&list.candidates[0].candidate_id)
        .unwrap()
}
#[test]
fn capture_choice_after_reopen_preserves_local_runtime_revision_and_updates_live_minimization() {
    let mut f = Fixture::new();
    let mut current = f.store.enable_capture_policy().unwrap();
    current.recording = true;
    current.titles = true;
    current.paused_until = Some(chrono::Utc::now() + chrono::Duration::hours(1));
    let current = f.store.set_capture_policy(current).unwrap();
    let mut preferences = aw_models::SyncCapturePreferencesV1::from_policy(&current);
    preferences.titles = false;
    let bucket = window_bucket();
    f.store.create_bucket(&bucket).unwrap();
    f.reopen();
    assert!(f.store.capture_policy().is_err());
    f.apply(f.manifest(
        "capture.minimization",
        portable(json!(preferences)),
        1,
        1,
        [0; 32],
    ))
    .unwrap();
    let preview = review_first(&f);
    f.store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .unwrap();
    let accepted = f.store.capture_policy().unwrap();
    assert_eq!(accepted.revision, current.revision + 1);
    assert_eq!(accepted.paused_until, current.paused_until);
    assert_eq!(accepted.recording, current.recording);
    assert!(!accepted.titles);
    assert!(accepted.effective_from > current.effective_from);
    let imported = f
        .store
        .import_events(&bucket.id, &[window_event()])
        .unwrap();
    assert_eq!(imported.len(), 1);
    assert!(!imported[0].data.contains_key("title"));
    f.reopen();
    let durable: aw_models::CapturePolicy = serde_json::from_str(
        &f.store
            .get_key_value("peakactivity.capture_policy")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(durable, accepted);
}
#[test]
fn protected_decisions_reject_array_ambiguous_and_oversize_metadata() {
    let mut raws=vec![
        "[1,1,\"settings.theme\",[]]".to_owned(),
        "{\"schema_version\":1,\"schema_version\":1,\"key_epoch\":1,\"field\":\"settings.theme\",\"candidate_ids\":[]}".into(),
        json!({"schema_version":1,"key_epoch":1,"field":"settings.theme","candidate_ids":[],"trusted":true}).to_string(),
        json!({"schema_version":2,"key_epoch":1,"field":"settings.theme","candidate_ids":[]}).to_string(),
        json!({"schema_version":1,"key_epoch":1,"field":"settings.views","candidate_ids":[]}).to_string(),
        json!({"schema_version":1,"key_epoch":1,"field":"settings.theme","candidate_ids":["bad"]}).to_string(),
        json!({"schema_version":1,"key_epoch":1,"field":"settings.theme","candidate_ids":["a".repeat(64),"a".repeat(64)]}).to_string(),
    ];
    raws.push(format!(
        "{}{}",
        json!({"schema_version":1,"key_epoch":1,"field":"settings.theme","candidate_ids":[]}),
        " ".repeat(aw_models::SYNC_MAX_CHUNK_BYTES)
    ));
    for raw in raws {
        let mut f = Fixture::new();
        f.apply(f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]))
            .unwrap();
        f.store.close();
        let conn = rusqlite::Connection::open(&f.path).unwrap();
        conn.pragma_update(None, "key", f.key.as_str()).unwrap();
        conn.execute("INSERT INTO key_value(key,value,last_modified) VALUES('peakactivity.sync_policy_decisions.settings.theme',?1,1)",[raw]).unwrap();
        drop(conn);
        f.reopen();
        assert!(f.store.list_sync_policy_candidates(None, 256).is_err());
    }
}
#[test]
fn current_policy_read_rejects_over_limit_epoch_history_before_json_scan() {
    let mut f = Fixture::new();
    f.store.close();
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    conn.pragma_update(None, "key", f.key.as_str()).unwrap();
    conn.execute_batch("WITH RECURSIVE counters(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM counters WHERE n<100001) INSERT INTO sync_operations(device_id,counter,key_epoch,operation_json,content_hash) SELECT zeroblob(16),n,1,'{}',zeroblob(32) FROM counters;").unwrap();
    drop(conn);
    f.reopen();
    assert!(f.store.list_sync_policy_candidates(None, 256).is_err());
}
#[test]
fn same_value_new_signed_counter_and_key_epoch_stale_previous_review() {
    let f = Fixture::new();
    let first = f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]);
    f.apply(first.clone()).unwrap();
    let old = review_first(&f);
    let parent = URL_SAFE_NO_PAD
        .decode(first.head_hash)
        .unwrap()
        .try_into()
        .unwrap();
    f.apply(f.manifest("settings.theme", portable(json!("light")), 2, 2, parent))
        .unwrap();
    assert!(f
        .store
        .choose_sync_policy(choice(&old, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    let fresh = review_first(&f);
    assert_ne!(old.candidate.candidate_id, fresh.candidate.candidate_id);
    let snapshot = aw_datastore::SyncSnapshotV1::new(
        [0x85; 16],
        vec![aw_models::SyncEnvelopeV1 {
            schema_version: 1,
            object_id: URL_SAFE_NO_PAD.encode([0x86; 16]),
            vault_id: URL_SAFE_NO_PAD.encode(VAULT),
            key_epoch: 2,
            nonce: URL_SAFE_NO_PAD.encode([0x87; 24]),
            ciphertext: URL_SAFE_NO_PAD.encode([0x88; 32]),
        }],
    );
    f.store
        .rotate_sync_key_material(
            SyncKeyMaterial::new(Zeroizing::new([0x89; 32]), VAULT, 2, [0x90; 24], [0x91; 48]),
            snapshot,
            None,
            "2026-10-14T01:00:00Z".into(),
        )
        .unwrap();
    assert!(f
        .store
        .choose_sync_policy(choice(&fresh, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    assert!(f.store.get_key_value("settings.theme").is_err());
}
#[test]
fn accepted_privacy_rules_update_live_filter_and_removal_breaks_heartbeat_merge() {
    let f = Fixture::new();
    let bucket = window_bucket();
    f.store.create_bucket(&bucket).unwrap();
    let mut capture = f.store.enable_capture_policy().unwrap();
    capture.recording = true;
    f.store.set_capture_policy(capture).unwrap();
    f.store
        .heartbeat(&bucket.id, window_event(), 100.0)
        .unwrap();
    let rules = json!([{"enabled":true,"bucket_prefix":"aw-watcher-window_","field":"app","pattern":"Editor","action":"drop","replacement":null}]);
    let first = f.manifest("settings.privacy_filters", portable(rules), 1, 1, [0; 32]);
    f.apply(first.clone()).unwrap();
    let preview = review_first(&f);
    f.store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .unwrap();
    assert!(f
        .store
        .import_events(&bucket.id, &[window_event()])
        .unwrap()
        .is_empty());
    assert!(f
        .store
        .heartbeat(&bucket.id, window_event(), 100.0)
        .unwrap()
        .data
        .is_empty());
    let parent = URL_SAFE_NO_PAD
        .decode(first.head_hash)
        .unwrap()
        .try_into()
        .unwrap();
    f.apply(f.manifest(
        "settings.privacy_filters",
        portable(json!([])),
        2,
        2,
        parent,
    ))
    .unwrap();
    let preview = review_first(&f);
    f.store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .unwrap();
    f.store
        .heartbeat(&bucket.id, window_event(), 100.0)
        .unwrap();
    assert_eq!(
        f.store
            .get_events_unclipped(&bucket.id, None, None, None)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn capture_and_privacy_choice_failures_preserve_live_cache_durable_state_and_journal() {
    for capture in [true, false] {
        for commit in [true, false] {
            let mut f = Fixture::new();
            let bucket = window_bucket();
            f.store.create_bucket(&bucket).unwrap();
            let mut local = f.store.enable_capture_policy().unwrap();
            local.recording = true;
            local.titles = true;
            let local = f.store.set_capture_policy(local).unwrap();
            let rules = json!([{"enabled":true,"bucket_prefix":"aw-watcher-window_","field":"app","pattern":"Editor","action":"drop","replacement":null}]);
            if !capture {
                f.store
                    .set_key_value("settings.privacy_filters", &rules.to_string())
                    .unwrap();
            }
            f.store.begin_sync_baseline().unwrap();
            let (field, value) = if capture {
                let mut prefs = aw_models::SyncCapturePreferencesV1::from_policy(&local);
                prefs.titles = false;
                ("capture.minimization", json!(prefs))
            } else {
                ("settings.privacy_filters", json!([]))
            };
            f.apply(f.manifest(field, portable(value), 1, 1, [0; 32]))
                .unwrap();
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
            let local = f.store.enable_capture_policy().unwrap();
            let preview = review_first(&f);
            assert!(f
                .store
                .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
                .is_err());
            let active = f.store.capture_policy().unwrap();
            assert_eq!(active.revision, local.revision);
            assert_eq!(active.titles, local.titles);
            if commit {
                assert!(!active.recording);
            }
            assert_eq!(
                f.store.list_sync_operations(LOCAL, 1, 0, 256).unwrap(),
                before
            );
            let events = f
                .store
                .import_events(&bucket.id, &[window_event()])
                .unwrap();
            if capture {
                assert_eq!(events.len(), 1);
                assert!(events[0].data.contains_key("title"));
            } else {
                assert!(events.is_empty());
            }
            f.reopen();
            let durable: aw_models::CapturePolicy = serde_json::from_str(
                &f.store
                    .get_key_value("peakactivity.capture_policy")
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(durable, local);
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
}
#[test]
fn selected_policy_hash_or_writer_corruption_is_rejected() {
    for change_writer in [true, false] {
        let mut f = Fixture::new();
        f.apply(f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]))
            .unwrap();
        f.store.close();
        let conn = rusqlite::Connection::open(&f.path).unwrap();
        conn.pragma_update(None, "key", f.key.as_str()).unwrap();
        if change_writer {
            let raw: String = conn
                .query_row(
                    "SELECT operation_json FROM sync_operations LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let mut op: Value = serde_json::from_str(&raw).unwrap();
            op["device_id"] = json!(URL_SAFE_NO_PAD.encode(LOCAL));
            let raw = op.to_string();
            let hash = ring::digest::digest(&ring::digest::SHA256, raw.as_bytes());
            conn.execute(
                "UPDATE sync_operations SET operation_json=?1,content_hash=?2",
                rusqlite::params![raw, hash.as_ref()],
            )
            .unwrap();
        } else {
            conn.execute("UPDATE sync_operations SET content_hash=zeroblob(32)", [])
                .unwrap();
        }
        drop(conn);
        f.reopen();
        assert!(f.store.list_sync_policy_candidates(None, 256).is_err());
    }
}

#[test]
fn newly_paired_equal_value_candidate_invalidates_retained_candidate_review() {
    let f = Fixture::new();
    f.apply(f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]))
        .unwrap();
    let preview = review_first(&f);
    let second_id = [0x92; 16];
    let second = DeviceIdentityV1::from_bytes(
        second_id,
        Zeroizing::new([0x93; 32]),
        Zeroizing::new([0x94; 32]),
    );
    let public = second.public_identity();
    f.store
        .record_sync_pairing(
            None,
            [0x95; 16],
            second_id,
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
            "2026-10-14T01:00:00Z".into(),
        )
        .unwrap();
    let operation = create_policy_change(
        second_id,
        1,
        1,
        BTreeMap::from([("settings.theme".into(), portable(json!("light")))]),
    )
    .unwrap();
    let manifest =
        SyncManifestV1::new_signed(&second, VAULT, 1, 1, [0; 32], vec![operation]).unwrap();
    f.apply(manifest).unwrap();
    assert_eq!(
        f.store
            .list_sync_policy_candidates(None, 256)
            .unwrap()
            .candidates
            .len(),
        2
    );
    assert!(f
        .store
        .choose_sync_policy(choice(&preview, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    let fresh = f
        .store
        .preview_sync_policy_candidate(&preview.candidate.candidate_id)
        .unwrap();
    assert_ne!(preview.expected_review_sha256, fresh.expected_review_sha256);
    f.store
        .choose_sync_policy(choice(&fresh, SyncPolicyDecisionV1::AcceptRemote))
        .unwrap();
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
}

#[test]
fn reopened_worker_cannot_accept_old_review_even_when_persisted_policy_is_identical() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.apply(f.manifest("settings.theme", portable(json!("light")), 1, 1, [0; 32]))
        .unwrap();
    let old = review_first(&f);
    f.reopen();
    assert!(f
        .store
        .choose_sync_policy(choice(&old, SyncPolicyDecisionV1::AcceptRemote))
        .is_err());
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    let fresh = review_first(&f);
    assert_eq!(fresh.candidate.candidate_id, old.candidate.candidate_id);
    assert_ne!(fresh.expected_review_sha256, old.expected_review_sha256);
    f.store
        .choose_sync_policy(choice(&fresh, SyncPolicyDecisionV1::AcceptRemote))
        .unwrap();
    f.reopen();
    assert!(f
        .store
        .list_sync_policy_candidates(None, 256)
        .unwrap()
        .candidates
        .is_empty());
}

#[test]
fn policy_context_is_live_worker_owned_shared_by_clones_and_rotates_on_real_unlock() {
    let f = Fixture::new();
    let first = f.store.get_sync_policy_context().unwrap();
    assert_eq!(first.schema_version, 1);
    assert!(aw_models::valid_lower_hex(&first.context_id, 64));
    assert_eq!(f.store.clone().get_sync_policy_context().unwrap(), first);
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    assert_eq!(f.store.get_sync_policy_context().unwrap(), first);
    f.store.lock().unwrap();
    assert!(f.store.get_sync_policy_context().is_err());
    f.store
        .unlock_encrypted(f.path.to_string_lossy().into_owned(), f.key.clone())
        .unwrap();
    assert_ne!(
        f.store.get_sync_policy_context().unwrap().context_id,
        first.context_id
    );
    assert!(Datastore::new_in_memory(false)
        .get_sync_policy_context()
        .is_err());
}
