#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::{Datastore, SyncDeviceIdentity, SyncKeyMaterial};
use aw_models::{
    EgressUserPolicyV1, SignedEgressPolicyBundleV1, SyncOperationKindV1, SyncPolicyValueV1,
};
use aw_sync_e2ee::SyncOperationV1;
use serde_json::json;
use std::path::PathBuf;
use zeroize::Zeroizing;

const DEVICE: [u8; 16] = [0x41; 16];
struct Fixture {
    store: Datastore,
    path: PathBuf,
    key: String,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "peak-policy-journal-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = "b".repeat(64);
        let store =
            Datastore::open_encrypted(path.to_string_lossy().into_owned(), key.clone()).unwrap();
        store
            .create_sync_device_identity(&SyncDeviceIdentity::new(
                DEVICE,
                Zeroizing::new([0x42; 32]),
                Zeroizing::new([0x43; 32]),
            ))
            .unwrap();
        store
            .install_sync_key_material(&SyncKeyMaterial::new(
                Zeroizing::new([0x44; 32]),
                [0x45; 16],
                1,
                [0x46; 24],
                [0x47; 48],
            ))
            .unwrap();
        Self { store, path, key }
    }
    fn reopen(&mut self) {
        self.store.close();
        self.store =
            Datastore::open_encrypted(self.path.to_string_lossy().into_owned(), self.key.clone())
                .unwrap();
    }
    fn raw(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(&self.path).unwrap();
        conn.pragma_update(None, "key", self.key.as_str()).unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        conn
    }
    fn operations(&self) -> Vec<SyncOperationV1> {
        self.store
            .list_sync_operations(DEVICE, 1, 0, 256)
            .unwrap()
            .iter()
            .map(|o| serde_json::from_str(&o.operation_json).unwrap())
            .collect()
    }
    fn fail_journal(&mut self) {
        self.store.close();
        self.raw().execute_batch("CREATE TRIGGER fail_policy_journal BEFORE INSERT ON sync_operations BEGIN SELECT RAISE(ABORT,'synthetic policy journal failure'); END;").unwrap();
        self.reopen();
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
fn value(op: &SyncOperationV1, field: &str) -> SyncPolicyValueV1 {
    serde_json::from_value(op.fields[field].clone()).unwrap()
}
fn filter() -> String {
    json!([{"enabled":true,"bucket_prefix":null,"field":"title","pattern":"secret","action":"drop","replacement":null}]).to_string()
}

#[test]
fn policy_baseline_seeds_current_state_once_without_preparation_history() {
    let f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.store
        .set_key_value("settings.privacy_filters", &filter())
        .unwrap();
    assert!(f.operations().is_empty());
    assert!(f.store.begin_sync_baseline().unwrap().complete);
    let operations = f.operations();
    assert_eq!(operations.len(), 21);
    assert!(operations
        .iter()
        .all(|op| op.kind == SyncOperationKindV1::PolicyChange
            && op.policy_version == Some(op.counter)));
    let theme = operations
        .iter()
        .find(|op| op.fields.contains_key("settings.theme"))
        .unwrap();
    assert_eq!(value(theme, "settings.theme").value, json!("dark"));
    let classes = operations
        .iter()
        .find(|op| op.fields.contains_key("settings.classes"))
        .unwrap();
    assert!(!value(classes, "settings.classes").present);
    f.store.begin_sync_baseline().unwrap();
    assert!(f.operations() == operations);
}

#[test]
fn policy_settings_set_cas_delete_journal_only_actual_changes_and_reopen() {
    let mut f = Fixture::new();
    f.store.begin_sync_baseline().unwrap();
    let baseline = f.operations().len();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    assert_eq!(f.operations().len(), baseline + 1);
    f.store
        .set_key_value("settings.theme", " \"dark\" ")
        .unwrap();
    assert_eq!(f.operations().len(), baseline + 1);
    assert!(!f
        .store
        .compare_and_set_key_value("settings.theme", Some("\"wrong\""), Some("\"light\""))
        .unwrap());
    assert_eq!(f.operations().len(), baseline + 1);
    assert!(f
        .store
        .compare_and_set_key_value("settings.theme", Some(" \"dark\" "), Some("\"light\""))
        .unwrap());
    assert_eq!(f.operations().len(), baseline + 2);
    f.store.delete_key_value("settings.theme").unwrap();
    f.store.delete_key_value("settings.theme").unwrap();
    let operations = f.operations();
    assert_eq!(operations.len(), baseline + 3);
    assert!(!value(operations.last().unwrap(), "settings.theme").present);
    f.reopen();
    assert!(f.operations() == operations);
    assert!(f.store.get_key_value("settings.theme").is_err());
}

#[test]
fn policy_setting_ack_is_durable_even_without_capture_enabled() {
    let f = Fixture::new();
    f.store.begin_sync_baseline().unwrap();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    assert_eq!(
        f.raw()
            .query_row(
                "SELECT value FROM key_value WHERE key='settings.theme'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "\"dark\""
    );
    assert_eq!(
        f.raw()
            .query_row("SELECT count(*) FROM sync_operations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        22
    );
}

#[test]
fn policy_journal_failure_rolls_back_setting_cas_delete_and_counter() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.store.begin_sync_baseline().unwrap();
    let before = f.operations();
    f.fail_journal();
    assert!(f
        .store
        .set_key_value("settings.theme", "\"light\"")
        .is_err());
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert!(f
        .store
        .compare_and_set_key_value("settings.theme", Some("\"dark\""), Some("\"light\""))
        .is_err());
    assert!(f.store.delete_key_value("settings.theme").is_err());
    assert!(f.operations() == before);
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    f.store.close();
    assert_eq!(
        f.raw()
            .query_row(
                "SELECT last_counter FROM sync_device_counters WHERE device_id=?1",
                [&DEVICE[..]],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        21
    );
    f.reopen();
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
}

#[test]
fn policy_capture_runtime_and_startup_are_not_portable_edits() {
    let mut f = Fixture::new();
    f.store.enable_capture_policy().unwrap();
    f.store.begin_sync_baseline().unwrap();
    let before = f.operations();
    let mut policy = f.store.capture_policy().unwrap();
    policy.recording = true;
    f.store.set_capture_policy(policy).unwrap();
    f.store.pause_capture().unwrap();
    f.reopen();
    f.store.enable_capture_policy().unwrap();
    assert!(f.operations() == before);
    let mut policy = f.store.capture_policy().unwrap();
    policy.titles = true;
    f.store.set_capture_policy(policy).unwrap();
    let operations = f.operations();
    assert_eq!(operations.len(), before.len() + 1);
    let prefs = value(operations.last().unwrap(), "capture.minimization").value;
    assert_eq!(prefs["titles"], json!(true));
    for key in ["recording", "paused_until", "revision", "effective_from"] {
        assert!(prefs.get(key).is_none());
    }
}

#[test]
fn policy_capture_and_privacy_journal_failure_preserve_active_cache() {
    let mut f = Fixture::new();
    f.store.enable_capture_policy().unwrap();
    let mut policy = f.store.capture_policy().unwrap();
    policy.titles = true;
    f.store.set_capture_policy(policy).unwrap();
    f.store
        .set_key_value("settings.privacy_filters", &filter())
        .unwrap();
    f.store.begin_sync_baseline().unwrap();
    f.fail_journal();
    f.store.enable_capture_policy().unwrap();
    let before = f.store.capture_policy().unwrap();
    let mut next = before.clone();
    next.titles = false;
    assert!(f.store.set_capture_policy(next).is_err());
    assert_eq!(f.store.capture_policy().unwrap(), before);
    assert!(f
        .store
        .set_key_value("settings.privacy_filters", "[]")
        .is_err());
    assert_eq!(
        f.store.get_key_value("settings.privacy_filters").unwrap(),
        filter()
    );
    assert!(f.store.reset_privacy().is_err());
    assert_eq!(f.store.capture_policy().unwrap(), before);
    assert_eq!(
        f.store.get_key_value("settings.privacy_filters").unwrap(),
        filter()
    );
}

#[test]
fn policy_egress_effective_user_is_journaled_once_across_first_bundle_and_updates() {
    let f = Fixture::new();
    f.store.begin_sync_baseline().unwrap();
    let before = f.operations().len();
    let user: EgressUserPolicyV1 = serde_json::from_value(
        json!({"schema_version":1,"user_rules":[],"safe_zone_patterns":[],"after_hours":null}),
    )
    .unwrap();
    let bundle:SignedEgressPolicyBundleV1=serde_json::from_value(json!({"schema_version":1,"signer_key_id":"synthetic-root","signature":vec![0u8;64],"bundle":{"schema_version":1,"version":1,"hard_deny_version":1,"destinations":[],"purposes":[],"organization_rules":[]}})).unwrap();
    f.store.store_egress_policy_state(&bundle, &user).unwrap();
    assert_eq!(f.operations().len(), before + 1);
    assert!(f
        .operations()
        .last()
        .unwrap()
        .fields
        .contains_key("egress.signed_bundle"));
    let mut changed = user.clone();
    changed.after_hours = Some(aw_models::AfterHoursV1 {
        weekdays: vec![1],
        start_minute: 60,
        end_minute: 120,
    });
    f.store.store_egress_user_policy(&changed).unwrap();
    assert_eq!(f.operations().len(), before + 2);
    assert!(f
        .operations()
        .last()
        .unwrap()
        .fields
        .contains_key("egress.user_policy"));
    f.store.store_egress_user_policy(&changed).unwrap();
    f.store
        .store_egress_policy_state(&bundle, &changed)
        .unwrap();
    assert_eq!(f.operations().len(), before + 2);
}

#[test]
fn policy_baseline_seed_failure_leaves_preparation_and_counters_unchanged() {
    let mut f = Fixture::new();
    f.fail_journal();
    assert!(f.store.begin_sync_baseline().is_err());
    assert!(f.store.sync_baseline_progress().unwrap().is_none());
    assert!(f.operations().is_empty());
    f.store.close();
    assert_eq!(
        f.raw()
            .query_row("SELECT count(*) FROM sync_device_counters", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn policy_key_write_failure_returns_without_panicking_the_worker() {
    let mut f = Fixture::new();
    f.store.set_key_value("settings.theme", "\"dark\"").unwrap();
    f.store.close();
    f.raw().execute_batch("CREATE TRIGGER reject_local_theme BEFORE INSERT ON key_value WHEN NEW.key='settings.theme' BEGIN SELECT RAISE(ABORT,'synthetic key failure'); END;").unwrap();
    f.reopen();
    assert!(f
        .store
        .set_key_value("settings.theme", "\"light\"")
        .is_err());
    assert_eq!(f.store.get_key_value("settings.theme").unwrap(), "\"dark\"");
    assert!(f.operations().is_empty());
}

#[test]
fn policy_actual_commit_failure_preserves_portable_capture_cache_and_journal() {
    let mut f = Fixture::new();
    f.store.enable_capture_policy().unwrap();
    let mut initial = f.store.capture_policy().unwrap();
    initial.titles = true;
    f.store.set_capture_policy(initial).unwrap();
    f.store.begin_sync_baseline().unwrap();
    let operations = f.operations();
    f.store.close();
    f.raw().execute_batch("CREATE TABLE policy_commit_parent(id INTEGER PRIMARY KEY);
      CREATE TABLE policy_commit_child(parent_id INTEGER NOT NULL REFERENCES policy_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
      CREATE TRIGGER fail_capture_commit AFTER INSERT ON key_value WHEN NEW.key='peakactivity.capture_policy' AND json_extract(NEW.value,'$.titles')=0
      BEGIN INSERT INTO policy_commit_child(parent_id) VALUES(1); END;").unwrap();
    f.reopen();
    f.store.enable_capture_policy().unwrap();
    let before = f.store.capture_policy().unwrap();
    let mut next = before.clone();
    next.titles = false;
    assert!(f.store.set_capture_policy(next).is_err());
    let cached = f.store.capture_policy().unwrap();
    assert_eq!(cached.titles, before.titles);
    assert_eq!(cached.revision, before.revision);
    f.store.close();
    let persisted: aw_models::CapturePolicy = serde_json::from_str(
        &f.raw()
            .query_row(
                "SELECT value FROM key_value WHERE key='peakactivity.capture_policy'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(persisted, before);
    f.reopen();
    assert!(f.operations() == operations);
    assert_eq!(
        f.raw()
            .query_row("SELECT count(*) FROM policy_commit_child", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn policy_stop_transfer_keeps_journaling_local_changes() {
    let f=Fixture::new();f.store.begin_sync_baseline().unwrap();let before=f.operations().len();
    f.store.set_sync_enabled(false,None,None).unwrap();assert!(!f.store.sync_enabled().unwrap());
    f.store.set_key_value("settings.theme","\"dark\"").unwrap();assert_eq!(f.operations().len(),before+1);
}

#[test]
fn policy_edits_during_event_baseline_are_journaled_once() {
    let f=Fixture::new();let mut bucket=aw_models::Bucket {bid:None,id:"policy-events".into(),_type:"app".into(),client:"test".into(),hostname:"test".into(),created:None,data:Default::default(),metadata:Default::default(),events:None,last_updated:None};
    bucket.events=Some(aw_models::TryVec::new(Vec::new()));f.store.create_bucket(&bucket).unwrap();
    f.store.insert_events("policy-events",&[aw_models::Event::new(chrono::Utc::now(),chrono::Duration::seconds(1),json!({"app":"Editor"}).as_object().unwrap().clone())]).unwrap();
    assert!(!f.store.begin_sync_baseline().unwrap().complete);f.store.set_key_value("settings.theme","\"dark\"").unwrap();
    assert!(f.store.process_sync_baseline_batch(1).unwrap().complete);let operations=f.operations();
    assert_eq!(operations.iter().filter(|op|op.fields.contains_key("settings.theme")).count(),2);
    assert_eq!(operations.iter().filter(|op|op.kind==SyncOperationKindV1::Upsert).count(),1);
    f.store.begin_sync_baseline().unwrap();assert!(f.operations()==operations);
}

#[test]
fn policy_wire_admission_checks_complete_manifest_and_rolls_back_oversize() {
    let f=Fixture::new();f.store.begin_sync_baseline().unwrap();let before=f.operations();
    let over=json!("x".repeat(aw_models::SYNC_POLICY_MAX_FIELD_BYTES_V1)).to_string();
    assert!(f.store.set_key_value("settings.always_active_pattern",&over).is_err());assert!(f.store.get_key_value("settings.always_active_pattern").is_err());assert!(f.operations()==before);
    let overhead=serde_json::to_vec(&SyncPolicyValueV1 {schema_version:1,present:true,value:json!("")}).unwrap().len();
    let exact=json!("x".repeat(aw_models::SYNC_POLICY_MAX_FIELD_BYTES_V1-overhead)).to_string();f.store.set_key_value("settings.always_active_pattern",&exact).unwrap();
    let operations=f.operations();assert_eq!(operations.len(),before.len()+1);
    let signer=aw_sync_e2ee::DeviceIdentityV1::from_bytes(DEVICE,Zeroizing::new([0x42;32]),Zeroizing::new([0x43;32]));
    let manifest=aw_sync_e2ee::SyncManifestV1::new_signed(&signer,[0x45;16],1,1,[0;32],vec![operations.last().unwrap().clone()]).unwrap();
    assert!(serde_json::to_vec(&manifest).unwrap().len()<=aw_models::SYNC_MAX_CHUNK_BYTES);
}
