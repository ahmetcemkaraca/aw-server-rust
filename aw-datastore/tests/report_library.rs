#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::Datastore;
use aw_models::{
    ReportExecutionErrorV1, ReportFeatureAccessV1, ReportLibraryV1, UpdateReportLibraryRequestV1,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Vault {
    store: Datastore,
    directory: PathBuf,
}
impl Vault {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "peak-report-library-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let store = Datastore::open_encrypted(
            directory.join("activity.db").to_string_lossy().into_owned(),
            "a".repeat(64),
        )
        .unwrap();
        Self { store, directory }
    }
}
impl Drop for Vault {
    fn drop(&mut self) {
        self.store.close();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn report_library_generic_set_is_not_a_paid_write_path() {
    let vault = Vault::new();
    assert!(vault
        .store
        .set_key_value(
            "reports.library.v1",
            r#"{"schema_version":1,"revision":1,"templates":[],"rule_packs":[]}"#
        )
        .is_err());
    assert!(vault.store.get_key_value("reports.library.v1").is_err());
    vault
        .store
        .set_key_value("settings.report-free-test", "preserved")
        .unwrap();
    assert_eq!(
        vault
            .store
            .get_key_value("settings.report-free-test")
            .unwrap(),
        "preserved"
    );
}

#[test]
fn report_library_generic_cas_is_not_a_paid_write_path() {
    let vault = Vault::new();
    assert!(vault
        .store
        .compare_and_set_key_value("reports.library.v1", None, Some("{}"))
        .is_err());
    assert!(vault.store.get_key_value("reports.library.v1").is_err());
}

#[test]
fn report_library_generic_delete_cannot_reset_native_revision() {
    let vault = Vault::new();
    assert!(vault.store.delete_key_value("reports.library.v1").is_err());
}

struct Access {
    granted: AtomicBool,
    calls: AtomicUsize,
}
impl Access {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            granted: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        })
    }
}
impl ReportFeatureAccessV1 for Access {
    fn with_access(
        &self,
        action: Box<dyn FnOnce() -> Result<(), ReportExecutionErrorV1> + '_>,
    ) -> Result<(), ReportExecutionErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.granted.load(Ordering::SeqCst) {
            return Err(ReportExecutionErrorV1::EntitlementUnavailable);
        }
        action()
    }
}
fn proposed(revision: u64, name: &str, version: u64) -> UpdateReportLibraryRequestV1 {
    serde_json::from_value(serde_json::json!({"schema_version":1,"expected_revision":revision,"library":{
        "schema_version":1,"revision":revision,"rule_packs":[],"templates":[{
            "id":"work","name":name,"content_version":version,"method_id":"work-time-report","method_version":1,
            "sections":["daily"],"category_paths":[],"break_time_seconds":60,"rule_pack":null
        }]}})).unwrap()
}

#[test]
fn report_library_typed_write_is_durable_and_native_revisioned() {
    let vault = Vault::new();
    let access = Access::new();
    assert_eq!(
        vault.store.report_library().unwrap(),
        ReportLibraryV1::default()
    );
    let saved = vault
        .store
        .update_report_library(proposed(0, "Work", 1), access.clone())
        .unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(access.calls.load(Ordering::SeqCst), 1);
    vault.store.close();
    let reopened = Datastore::open_encrypted(
        vault
            .directory
            .join("activity.db")
            .to_string_lossy()
            .into_owned(),
        "a".repeat(64),
    )
    .unwrap();
    assert_eq!(reopened.report_library().unwrap(), saved);
    reopened.close();
}

#[test]
fn report_library_revision_growth_cannot_persist_an_unreadable_library() {
    let vault = Vault::new();
    let access = Access::new();
    for revision in 0..9 {
        vault
            .store
            .update_report_library(
                proposed(revision, &format!("Work {revision}"), revision + 1),
                access.clone(),
            )
            .unwrap();
    }
    let before = vault.store.report_library().unwrap();
    let mut request = proposed(9, "Expanded", 1);
    let template = request.library.templates.pop().unwrap();
    request.library.templates = (0..10)
        .map(|index| {
            let mut value = template.clone();
            value.id = format!("work-{index}");
            value.category_paths = (0..100)
                .map(|path| {
                    let mut parts = vec!["x".repeat(128); 8];
                    parts[0] = format!("{path:03}{}", "x".repeat(125));
                    parts
                })
                .collect();
            value
        })
        .collect();
    let limit = aw_models::REPORT_LIBRARY_MAX_BYTES_V1;
    let mut excess = serde_json::to_vec(&request.library).unwrap().len() - limit;
    for value in &mut request.library.templates {
        for path in &mut value.category_paths {
            for segment in path.iter_mut().skip(1) {
                let remove = excess.min(segment.len() - 1);
                segment.truncate(segment.len() - remove);
                excess -= remove;
            }
        }
    }
    assert_eq!(excess, 0);
    assert_eq!(serde_json::to_vec(&request.library).unwrap().len(), limit);
    request.validate().unwrap();
    assert!(matches!(
        vault.store.update_report_library(request, access.clone()),
        Err(ReportExecutionErrorV1::ByteLimit)
    ));
    assert_eq!(vault.store.report_library().unwrap(), before);
    access.granted.store(false, Ordering::SeqCst);
    let mut removal = before.clone();
    removal.templates.clear();
    assert_eq!(
        vault
            .store
            .update_report_library(
                UpdateReportLibraryRequestV1 {
                    schema_version: 1,
                    expected_revision: 9,
                    library: removal
                },
                access
            )
            .unwrap()
            .revision,
        10
    );
}

#[test]
fn report_library_revocation_keeps_noop_read_and_exact_removal_free() {
    let vault = Vault::new();
    let access = Access::new();
    let saved = vault
        .store
        .update_report_library(proposed(0, "Work", 1), access.clone())
        .unwrap();
    access.granted.store(false, Ordering::SeqCst);
    let same = UpdateReportLibraryRequestV1 {
        schema_version: 1,
        expected_revision: 1,
        library: saved.clone(),
    };
    assert_eq!(
        vault
            .store
            .update_report_library(same, access.clone())
            .unwrap(),
        saved
    );
    assert_eq!(
        vault
            .store
            .update_report_library(proposed(1, "Changed", 2), access.clone()),
        Err(ReportExecutionErrorV1::EntitlementUnavailable)
    );
    let denied_calls = access.calls.load(Ordering::SeqCst);
    let empty = UpdateReportLibraryRequestV1 {
        schema_version: 1,
        expected_revision: 1,
        library: ReportLibraryV1 {
            revision: 1,
            ..ReportLibraryV1::default()
        },
    };
    let removed = vault
        .store
        .update_report_library(empty, access.clone())
        .unwrap();
    assert_eq!(removed.revision, 2);
    assert!(removed.templates.is_empty());
    assert_eq!(access.calls.load(Ordering::SeqCst), denied_calls);
    assert_eq!(vault.store.report_library().unwrap(), removed);
    assert!(vault.store.get_key_value("reports.library.v1").is_ok());
}

#[test]
fn report_library_version_skip_and_stale_revision_preserve_exact_bytes() {
    let vault = Vault::new();
    let access = Access::new();
    vault
        .store
        .update_report_library(proposed(0, "Work", 1), access.clone())
        .unwrap();
    let before = vault.store.get_key_value("reports.library.v1").unwrap();
    for request in [
        proposed(0, "Stale", 2),
        proposed(1, "Changed", 3),
        proposed(1, "Changed", 1),
    ] {
        assert_eq!(
            vault.store.update_report_library(request, access.clone()),
            Err(ReportExecutionErrorV1::StaleConfiguration)
        );
        assert_eq!(
            vault.store.get_key_value("reports.library.v1").unwrap(),
            before
        );
    }
    assert_eq!(
        vault
            .store
            .update_report_library(proposed(1, "Changed", 2), access)
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn report_rules_hash_ignores_cosmetics_but_pins_order_rules_and_unicode() {
    use aw_datastore::report_calculation_sha256;
    use aw_models::ReportCategoryV1;
    let categories:Vec<ReportCategoryV1>=serde_json::from_value(serde_json::json!([
        {"name":["Łódź"],"rule":{"type":"regex","regex":"Editor"},"data":{"color":"red","score":"42"}},
        {"name":["Other"],"rule":{"type":null}}
    ])).unwrap();
    let hash = report_calculation_sha256(&categories).unwrap();
    assert_eq!(
        hash,
        "8922fc6e38273b095442628768049064f2acdd938408dbff2253d1559df826c5"
    );
    let mut changed = categories.clone();
    changed[0].id = Some(999);
    changed[0].data = None;
    changed[0].rule.ignore_case = Some(false);
    assert_eq!(report_calculation_sha256(&changed).unwrap(), hash);
    changed.swap(0, 1);
    assert_ne!(report_calculation_sha256(&changed).unwrap(), hash);
    let mut changed = categories.clone();
    changed[0].rule.regex = Some("Other".into());
    assert_ne!(report_calculation_sha256(&changed).unwrap(), hash);
    let mut changed = categories.clone();
    changed[0].name[0] = "Lodz".into();
    assert_ne!(report_calculation_sha256(&changed).unwrap(), hash);
}

fn reopen(vault: &Vault) -> Datastore {
    Datastore::open_encrypted(
        vault
            .directory
            .join("activity.db")
            .to_string_lossy()
            .into_owned(),
        "a".repeat(64),
    )
    .unwrap()
}
fn setup(vault: &Vault) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(vault.directory.join("activity.db")).unwrap();
    conn.pragma_update(None, "key", "a".repeat(64)).unwrap();
    conn
}

#[test]
fn report_library_commit_failure_preserves_normal_writes_and_releases_lease() {
    let vault = Vault::new();
    let access = Access::new();
    vault
        .store
        .update_report_library(proposed(0, "Work", 1), access.clone())
        .unwrap();
    let before = vault.store.get_key_value("reports.library.v1").unwrap();
    vault.store.close();
    {
        let mut conn = setup(&vault);
        assert_eq!(
            conn.pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        conn.execute_batch("CREATE TABLE report_commit_parent(id INTEGER PRIMARY KEY);
          CREATE TABLE report_commit_child(parent_id INTEGER NOT NULL REFERENCES report_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
          CREATE TRIGGER report_commit_failure AFTER INSERT ON key_value WHEN NEW.key='reports.library.v1'
          BEGIN INSERT INTO report_commit_child(parent_id) VALUES(1); END;").unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("INSERT OR REPLACE INTO key_value(key,value,last_modified) VALUES('reports.library.v1',?1,0)",[&before]).unwrap();
        assert_eq!(
            tx.query_row("SELECT count(*) FROM report_commit_child", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let failure = tx.commit().unwrap_err();
        assert_eq!(failure.sqlite_error().unwrap().extended_code, 787);
        assert!(conn.is_autocommit());
        assert_eq!(
            conn.query_row("SELECT count(*) FROM report_commit_child", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    let store = reopen(&vault);
    store
        .set_key_value("settings.report-before", "before")
        .unwrap();
    assert_eq!(
        store.update_report_library(proposed(1, "Updated", 2), access.clone()),
        Err(ReportExecutionErrorV1::DataIntegrity)
    );
    assert_eq!(access.calls.load(Ordering::SeqCst), 2);
    assert_eq!(store.get_key_value("reports.library.v1").unwrap(), before);
    store
        .set_key_value("settings.report-after", "after")
        .unwrap();
    store.force_commit().unwrap();
    store.close();
    let store = reopen(&vault);
    assert_eq!(
        store.get_key_value("settings.report-before").unwrap(),
        "before"
    );
    assert_eq!(
        store.get_key_value("settings.report-after").unwrap(),
        "after"
    );
    assert_eq!(store.get_key_value("reports.library.v1").unwrap(), before);
    store.close();
    setup(&vault).execute_batch("DROP TRIGGER report_commit_failure; DROP TABLE report_commit_child; DROP TABLE report_commit_parent;").unwrap();
    let store = reopen(&vault);
    assert_eq!(
        store
            .update_report_library(proposed(1, "Updated", 2), access)
            .unwrap()
            .revision,
        2
    );
    store.close();
}

#[test]
fn report_library_explicit_pin_repair_and_checked_versions() {
    let vault = Vault::new();
    let access = Access::new();
    let mut first = proposed(0, "Work", 1);
    first.library.rule_packs = serde_json::from_value(
        serde_json::json!([{"id":"rules","name":"Rules","content_version":1,"category_sets":[]}]),
    )
    .unwrap();
    first.library.templates[0].rule_pack =
        serde_json::from_value(serde_json::json!({"id":"rules","content_version":1})).unwrap();
    let original = vault
        .store
        .update_report_library(first, access.clone())
        .unwrap();
    let mut changed = UpdateReportLibraryRequestV1 {
        schema_version: 1,
        expected_revision: 1,
        library: original.clone(),
    };
    changed.library.rule_packs[0].name = "Changed".into();
    changed.library.rule_packs[0].content_version = 2;
    assert!(vault
        .store
        .update_report_library(changed.clone(), access.clone())
        .is_err());
    changed.library.templates[0]
        .rule_pack
        .as_mut()
        .unwrap()
        .content_version = 2;
    assert_eq!(
        vault
            .store
            .update_report_library(changed.clone(), access.clone()),
        Err(ReportExecutionErrorV1::StaleConfiguration)
    );
    changed.library.templates[0].content_version = 2;
    let saved = vault
        .store
        .update_report_library(changed, access.clone())
        .unwrap();
    assert_eq!(saved.revision, 2);
    let mut orphan = UpdateReportLibraryRequestV1 {
        schema_version: 1,
        expected_revision: 2,
        library: saved.clone(),
    };
    orphan.library.rule_packs.clear();
    assert!(vault
        .store
        .update_report_library(orphan, access.clone())
        .is_err());
    assert_eq!(vault.store.report_library().unwrap(), saved);
    vault.store.close();
    let mut overflow = saved;
    overflow.revision = u64::MAX;
    setup(&vault)
        .execute(
            "UPDATE key_value SET value=?1 WHERE key='reports.library.v1'",
            [serde_json::to_string(&overflow).unwrap()],
        )
        .unwrap();
    let store = reopen(&vault);
    let mut next = overflow.clone();
    next.templates.clear();
    next.rule_packs.clear();
    assert_eq!(
        store.update_report_library(
            UpdateReportLibraryRequestV1 {
                schema_version: 1,
                expected_revision: u64::MAX,
                library: next
            },
            access
        ),
        Err(ReportExecutionErrorV1::StaleConfiguration)
    );
    assert_eq!(store.report_library().unwrap(), overflow);
    store.close();
}

const IMPORT_KEYS: [&str; 4] = [
    "settings.category_sets",
    "settings.active_set_ids",
    "settings.classes",
    "reports.library.v1",
];
fn four_bytes(store: &Datastore) -> Vec<Option<String>> {
    IMPORT_KEYS
        .iter()
        .map(|key| store.get_key_value(key).ok())
        .collect()
}
fn package(id: &str) -> aw_models::PortableReportPackV1 {
    let categories: Vec<aw_models::ReportCategoryV1> = serde_json::from_value(serde_json::json!([
        {"name":["Imported"],"rule":{"type":"regex","regex":"Imported"}}
    ]))
    .unwrap();
    let hash = aw_datastore::report_calculation_sha256(&categories).unwrap();
    let mut request = proposed(0, "Imported", 97);
    request.library.rule_packs=serde_json::from_value(serde_json::json!([{"id":"rules","name":"Rules","content_version":44,"category_sets":[{"id":id,"calculation_sha256":hash}]}])).unwrap();
    request.library.templates[0].rule_pack =
        serde_json::from_value(serde_json::json!({"id":"rules","content_version":44})).unwrap();
    aw_models::PortableReportPackV1 {
        schema_version: 1,
        templates: request.library.templates,
        rule_packs: request.library.rule_packs,
        category_sets: vec![aw_models::ReportPortableCategorySetV1 {
            id: id.into(),
            name: "Portable display".into(),
            classes: categories,
        }],
    }
}

const POLICY_DEVICE: [u8; 16] = [0x61; 16];
fn enable_policy_journal(store: &Datastore) {
    store
        .create_sync_device_identity(&aw_datastore::SyncDeviceIdentity::new(
            POLICY_DEVICE,
            zeroize::Zeroizing::new([0x62; 32]),
            zeroize::Zeroizing::new([0x63; 32]),
        ))
        .unwrap();
    store
        .install_sync_key_material(&aw_datastore::SyncKeyMaterial::new(
            zeroize::Zeroizing::new([0x64; 32]),
            [0x65; 16],
            1,
            [0x66; 24],
            [0x67; 48],
        ))
        .unwrap();
    store.begin_sync_baseline().unwrap();
}
fn policy_operations(store: &Datastore) -> Vec<aw_sync_e2ee::SyncOperationV1> {
    store
        .list_sync_operations(POLICY_DEVICE, 1, 0, 256)
        .unwrap()
        .iter()
        .map(|row| serde_json::from_str(&row.operation_json).unwrap())
        .collect()
}

#[test]
fn report_import_journals_each_changed_portable_setting_in_the_owned_transaction() {
    let vault = Vault::new();
    enable_policy_journal(&vault.store);
    let access = Access::new();
    let before = four_bytes(&vault.store);
    let base = policy_operations(&vault.store).len();
    let prepared = vault
        .store
        .prepare_report_import(package("incoming"), access.clone())
        .unwrap();
    vault.store.commit_report_import(prepared, access).unwrap();
    let after = four_bytes(&vault.store);
    let operations = policy_operations(&vault.store);
    let expected = IMPORT_KEYS[..3]
        .iter()
        .enumerate()
        .filter(|(index, _)| before[*index] != after[*index])
        .map(|(_, key)| (*key).to_owned())
        .collect::<Vec<_>>();
    let actual = operations[base..]
        .iter()
        .flat_map(|op| op.fields.keys().cloned())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert!(!actual.is_empty());
    vault.store.close();
    let reopened = reopen(&vault);
    assert_eq!(four_bytes(&reopened), after);
    assert!(policy_operations(&reopened) == operations);
    reopened.close();
}

#[test]
fn report_import_policy_journal_failure_preserves_all_four_keys_and_counter() {
    let vault = Vault::new();
    enable_policy_journal(&vault.store);
    let before = four_bytes(&vault.store);
    let operations = policy_operations(&vault.store);
    vault.store.close();
    setup(&vault).execute_batch("CREATE TRIGGER fail_import_policy BEFORE INSERT ON sync_operations BEGIN SELECT RAISE(ABORT,'synthetic report policy failure'); END;").unwrap();
    let store = reopen(&vault);
    let access = Access::new();
    let prepared = store
        .prepare_report_import(package("incoming"), access.clone())
        .unwrap();
    assert_eq!(
        store.commit_report_import(prepared, access),
        Err(ReportExecutionErrorV1::DataIntegrity)
    );
    assert_eq!(four_bytes(&store), before);
    assert!(policy_operations(&store) == operations);
    store.close();
    assert_eq!(
        setup(&vault)
            .query_row(
                "SELECT last_counter FROM sync_device_counters WHERE device_id=?1",
                [&POLICY_DEVICE[..]],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        21
    );
}

#[test]
fn report_import_deferred_commit_failure_rolls_back_policy_journal_and_settings() {
    let vault = Vault::new();
    enable_policy_journal(&vault.store);
    let before = four_bytes(&vault.store);
    let operations = policy_operations(&vault.store);
    vault.store.close();
    setup(&vault).execute_batch("CREATE TABLE policy_report_parent(id INTEGER PRIMARY KEY);
      CREATE TABLE policy_report_child(parent_id INTEGER NOT NULL REFERENCES policy_report_parent(id) DEFERRABLE INITIALLY DEFERRED);
      CREATE TRIGGER fail_policy_report_commit AFTER INSERT ON key_value WHEN NEW.key='reports.library.v1' BEGIN INSERT INTO policy_report_child(parent_id) VALUES(1); END;").unwrap();
    let store = reopen(&vault);
    let access = Access::new();
    let prepared = store
        .prepare_report_import(package("incoming"), access.clone())
        .unwrap();
    assert_eq!(
        store.commit_report_import(prepared, access),
        Err(ReportExecutionErrorV1::DataIntegrity)
    );
    assert_eq!(four_bytes(&store), before);
    assert!(policy_operations(&store) == operations);
    store.close();
    let store = reopen(&vault);
    assert!(policy_operations(&store) == operations);
    assert_eq!(four_bytes(&store), before);
    store.close();
}

#[test]
fn report_import_materializes_identical_default_and_keeps_import_inactive() {
    for legacy in [None, Some("null"), Some("[]")] {
        let vault = Vault::new();
        let access = Access::new();
        if let Some(value) = legacy {
            vault
                .store
                .set_key_value("settings.classes", value)
                .unwrap();
        }
        let before = four_bytes(&vault.store);
        let preview = vault
            .store
            .prepare_report_import(package("default"), access.clone())
            .unwrap();
        assert_eq!(four_bytes(&vault.store), before);
        let metadata = preview.preview();
        metadata.validate().unwrap();
        assert_eq!(metadata.mappings[0].to_id, "default-import-1");
        assert_eq!(metadata.proposed_library.templates[0].content_version, 1);
        assert_eq!(metadata.proposed_library.rule_packs[0].content_version, 1);
        assert_eq!(
            metadata.proposed_library.templates[0]
                .rule_pack
                .as_ref()
                .unwrap()
                .content_version,
            1
        );
        let library = vault.store.commit_report_import(preview, access).unwrap();
        assert_eq!(library.revision, 1);
        let sets: serde_json::Value =
            serde_json::from_str(&vault.store.get_key_value("settings.category_sets").unwrap())
                .unwrap();
        assert_eq!(sets[0]["id"], "default");
        assert!(sets[0].get("name").is_none());
        if legacy == Some("[]") {
            assert_eq!(sets[0]["categories"], serde_json::json!([]));
        } else {
            assert_eq!(
                sets[0]["categories"],
                serde_json::from_str::<serde_json::Value>(
                    aw_models::REPORT_DEFAULT_CATEGORIES_JSON_V1
                )
                .unwrap()
            );
        }
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &vault
                    .store
                    .get_key_value("settings.active_set_ids")
                    .unwrap()
            )
            .unwrap(),
            serde_json::json!(["default"])
        );
        assert_eq!(
            vault
                .store
                .get_key_value("settings.classes")
                .ok()
                .as_deref(),
            legacy
        );
    }
}

#[test]
fn report_import_preserves_existing_active_priority_and_unicode_collisions() {
    let vault = Vault::new();
    let access = Access::new();
    let id = "Łódź Work";
    let stored = serde_json::json!([{"id":id,"categories":[{"name":["Prior"],"rule":{"type":null}}]},
        {"id":"second","categories":[]},{"id":"Łódź Work-import-1","categories":[]}]);
    let raw = serde_json::to_string_pretty(&stored).unwrap();
    vault
        .store
        .set_key_value("settings.category_sets", &raw)
        .unwrap();
    vault
        .store
        .set_key_value(
            "settings.active_set_ids",
            r#"["second", "Łódź Work", "unknown"]"#,
        )
        .unwrap();
    vault.store.set_key_value("settings.classes", "[]").unwrap();
    let before = four_bytes(&vault.store);
    let preview = vault
        .store
        .prepare_report_import(package(id), access.clone())
        .unwrap();
    assert_eq!(preview.preview().mappings[0].to_id, "Łódź Work-import-2");
    vault.store.commit_report_import(preview, access).unwrap();
    let after = four_bytes(&vault.store);
    assert_eq!(after[1], before[1]);
    assert_eq!(after[2], before[2]);
    let sets: serde_json::Value = serde_json::from_str(after[0].as_ref().unwrap()).unwrap();
    assert_eq!(&sets.as_array().unwrap()[..3], stored.as_array().unwrap());
}

#[test]
fn report_import_all_four_prior_keys_and_revocation_reject_without_partial_write() {
    for key in IMPORT_KEYS {
        let vault = Vault::new();
        let access = Access::new();
        let preview = vault
            .store
            .prepare_report_import(package("incoming"), access.clone())
            .unwrap();
        if key == "reports.library.v1" {
            vault
                .store
                .update_report_library(proposed(0, "Changed", 1), access.clone())
                .unwrap();
        } else {
            vault
                .store
                .set_key_value(
                    key,
                    if key == "settings.classes" {
                        "[]"
                    } else {
                        "null"
                    },
                )
                .unwrap();
        }
        let before = four_bytes(&vault.store);
        assert_eq!(
            vault.store.commit_report_import(preview, access),
            Err(ReportExecutionErrorV1::StaleConfiguration)
        );
        assert_eq!(four_bytes(&vault.store), before);
    }
    let vault = Vault::new();
    let access = Access::new();
    let preview = vault
        .store
        .prepare_report_import(package("incoming"), access.clone())
        .unwrap();
    access.granted.store(false, Ordering::SeqCst);
    let before = four_bytes(&vault.store);
    assert_eq!(
        vault.store.commit_report_import(preview, access),
        Err(ReportExecutionErrorV1::EntitlementUnavailable)
    );
    assert_eq!(four_bytes(&vault.store), before);
}

#[test]
fn report_portable_export_is_free_and_marks_unavailable_external_sets() {
    let vault = Vault::new();
    let access = Access::new();
    let preview = vault
        .store
        .prepare_report_import(package("incoming"), access.clone())
        .unwrap();
    vault
        .store
        .commit_report_import(preview, access.clone())
        .unwrap();
    access.granted.store(false, Ordering::SeqCst);
    let export = vault.store.export_report_library(true).unwrap();
    export.validate().unwrap();
    assert_eq!(export.package.category_sets.len(), 1);
    assert!(export.unavailable_set_ids.is_empty());
    vault
        .store
        .set_key_value("settings.category_sets", "[]")
        .unwrap();
    let export = vault.store.export_report_library(true).unwrap();
    assert!(export.package.category_sets.is_empty());
    assert_eq!(export.unavailable_set_ids, ["incoming"]);
    assert!(vault
        .store
        .export_report_library(false)
        .unwrap()
        .package
        .category_sets
        .is_empty());
    vault.store.set_key_value("settings.category_sets",r#"[{"id":"incoming","categories":[{"name":["Changed"],"rule":{"type":"unsupported"}}]}]"#).unwrap();
    let export = vault.store.export_report_library(true).unwrap();
    assert_eq!(export.unavailable_set_ids, ["incoming"]);
    assert_eq!(export.package.templates.len(), 1);
}

#[test]
fn report_import_real_commit_failure_rolls_back_all_four_keys() {
    let vault = Vault::new();
    let access = Access::new();
    vault.store.close();
    setup(&vault).execute_batch("CREATE TABLE report_commit_parent(id INTEGER PRIMARY KEY);
        CREATE TABLE report_commit_child(parent_id INTEGER NOT NULL REFERENCES report_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER report_commit_failure AFTER INSERT ON key_value WHEN NEW.key='reports.library.v1'
        BEGIN INSERT INTO report_commit_child(parent_id) VALUES(1); END;").unwrap();
    let store = reopen(&vault);
    let prepared = store
        .prepare_report_import(package("incoming"), access.clone())
        .unwrap();
    let before = four_bytes(&store);
    assert_eq!(
        store.commit_report_import(prepared, access),
        Err(ReportExecutionErrorV1::DataIntegrity)
    );
    assert_eq!(four_bytes(&store), before);
    store.close();
    let store = reopen(&vault);
    assert_eq!(four_bytes(&store), before);
    store.close();
    assert_eq!(
        setup(&vault)
            .query_row("SELECT count(*) FROM report_commit_child", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn report_library_paid_commit_is_visible_before_feature_lease_exits() {
    struct Witness {
        path: PathBuf,
        observed: AtomicBool,
    }
    impl ReportFeatureAccessV1 for Witness {
        fn with_access(
            &self,
            action: Box<dyn FnOnce() -> Result<(), ReportExecutionErrorV1> + '_>,
        ) -> Result<(), ReportExecutionErrorV1> {
            action()?;
            let conn = rusqlite::Connection::open(&self.path).unwrap();
            conn.pragma_update(None, "key", "a".repeat(64)).unwrap();
            conn.busy_timeout(std::time::Duration::from_millis(100))
                .unwrap();
            let raw: String = conn
                .query_row(
                    "SELECT value FROM key_value WHERE key='reports.library.v1'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let library: ReportLibraryV1 = serde_json::from_str(&raw).unwrap();
            self.observed.store(library.revision == 1, Ordering::SeqCst);
            Ok(())
        }
    }
    let vault = Vault::new();
    let witness = Arc::new(Witness {
        path: vault.directory.join("activity.db"),
        observed: AtomicBool::new(false),
    });
    vault
        .store
        .update_report_library(proposed(0, "Work", 1), witness.clone())
        .unwrap();
    assert!(witness.observed.load(Ordering::SeqCst));
}

#[test]
fn report_import_queued_access_is_checked_at_actual_worker_stage() {
    struct Held {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl ReportFeatureAccessV1 for Held {
        fn with_access(
            &self,
            action: Box<dyn FnOnce() -> Result<(), ReportExecutionErrorV1> + '_>,
        ) -> Result<(), ReportExecutionErrorV1> {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            action()
        }
    }
    let vault = Vault::new();
    let access = Access::new();
    let (entered, wait) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let held = Arc::new(Held {
        entered,
        release: std::sync::Mutex::new(wait_release),
    });
    let store = vault.store.clone();
    let first =
        std::thread::spawn(move || store.update_report_library(proposed(0, "Work", 1), held));
    wait.recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    let store = vault.store.clone();
    let queued_access = access.clone();
    let input = package("incoming");
    let queued = std::thread::spawn(move || store.prepare_report_import(input, queued_access));
    access.granted.store(false, Ordering::SeqCst);
    release.send(()).unwrap();
    first.join().unwrap().unwrap();
    assert!(matches!(
        queued.join().unwrap(),
        Err(ReportExecutionErrorV1::EntitlementUnavailable)
    ));
    assert_eq!(vault.store.report_library().unwrap().templates.len(), 1);
}

#[test]
fn report_import_reserves_incoming_suffix_ids_and_truncates_unicode_by_scalar() {
    let vault = Vault::new();
    let access = Access::new();
    let id = "界".repeat(42);
    let input = package(&id);
    let stored = serde_json::json!([{"id":id,"categories":[]}]);
    vault
        .store
        .set_key_value("settings.category_sets", &stored.to_string())
        .unwrap();
    let preview = vault
        .store
        .prepare_report_import(input, access.clone())
        .unwrap();
    let mapped = &preview.preview().mappings[0].to_id;
    assert!(mapped.len() <= 128);
    assert!(mapped.ends_with("-import-1"));
    assert!(mapped.starts_with('界'));
    vault
        .store
        .commit_report_import(preview, access.clone())
        .unwrap();
    let mut input = package("default");
    let mut second = input.category_sets[0].clone();
    second.id = "default-import-1".into();
    input.category_sets.push(second);
    vault
        .store
        .set_key_value(
            "settings.category_sets",
            r#"[{"id":"default","categories":[]}]"#,
        )
        .unwrap();
    let preview = vault.store.prepare_report_import(input, access).unwrap();
    assert_eq!(preview.preview().mappings[0].to_id, "default-import-2");
    assert_eq!(preview.preview().mappings[1].to_id, "default-import-1");
}

#[test]
fn report_import_empty_package_is_not_a_paid_revision_write() {
    let vault = Vault::new();
    let access = Access::new();
    let empty = aw_models::PortableReportPackV1 {
        schema_version: 1,
        templates: vec![],
        rule_packs: vec![],
        category_sets: vec![],
    };
    assert!(matches!(
        vault.store.prepare_report_import(empty, access.clone()),
        Err(ReportExecutionErrorV1::StaleConfiguration)
    ));
    assert_eq!(access.calls.load(Ordering::SeqCst), 0);
    assert_eq!(four_bytes(&vault.store), vec![None; 4]);
}

#[test]
fn report_import_rejects_ambiguous_stored_records_and_bounds_before_copy() {
    for raw in [
        r#"[{"id":"one","id":"two","categories":[]}]"#,
        r#"[["one",[]]]"#,
        r#"[{"id":"one","categories":[{"name":["Work"],"rule":{"type":"regex","regex":"Editor","script":"bad"}}]}]"#,
    ] {
        let vault = Vault::new();
        let access = Access::new();
        vault
            .store
            .set_key_value("settings.category_sets", raw)
            .unwrap();
        let before = four_bytes(&vault.store);
        assert!(vault
            .store
            .prepare_report_import(package("incoming"), access)
            .is_err());
        assert_eq!(four_bytes(&vault.store), before);
    }
    let vault = Vault::new();
    let access = Access::new();
    vault
        .store
        .set_key_value("settings.classes", &" ".repeat(32 * 1024 * 1024 + 1))
        .unwrap();
    assert!(matches!(
        vault
            .store
            .prepare_report_import(package("incoming"), access),
        Err(ReportExecutionErrorV1::ByteLimit)
    ));
    assert!(vault.store.get_key_value("reports.library.v1").is_err());
}

#[test]
fn report_library_owned_branch_preserves_native_capture_and_heartbeat_cache() {
    use aw_models::{Bucket, Event};
    use chrono::{Duration, Utc};
    let vault = Vault::new();
    let access = Access::new();
    let mut policy = vault.store.enable_capture_policy().unwrap();
    policy.recording = true;
    vault.store.set_capture_policy(policy).unwrap();
    let bucket = Bucket {
        bid: None,
        id: "aw-watcher-window_native-test".into(),
        _type: "currentwindow".into(),
        client: "report-test".into(),
        hostname: "native-test".into(),
        created: None,
        data: Default::default(),
        metadata: Default::default(),
        events: None,
        last_updated: None,
    };
    vault.store.create_bucket(&bucket).unwrap();
    let start = Utc::now();
    let event = |offset, app| {
        Event::new(
            start + Duration::seconds(offset),
            Duration::zero(),
            serde_json::json!({"app":app}).as_object().unwrap().clone(),
        )
    };
    vault
        .store
        .insert_events(&bucket.id, &[event(0, "Before")])
        .unwrap();
    vault
        .store
        .heartbeat(&bucket.id, event(2, "Pulse"), 2.0)
        .unwrap();
    vault
        .store
        .update_report_library(proposed(0, "Work", 1), access.clone())
        .unwrap();
    access.granted.store(false, Ordering::SeqCst);
    assert_eq!(
        vault
            .store
            .update_report_library(proposed(1, "Denied", 2), access),
        Err(ReportExecutionErrorV1::EntitlementUnavailable)
    );
    vault
        .store
        .heartbeat(&bucket.id, event(3, "Pulse"), 2.0)
        .unwrap();
    vault
        .store
        .set_key_value("settings.capture-after", "durable")
        .unwrap();
    vault.store.force_commit().unwrap();
    vault.store.close();
    let store = reopen(&vault);
    let events = store.get_events(&bucket.id, None, None, None).unwrap();
    assert_eq!(events.len(), 2);
    let pulse = events.iter().find(|e| e.data["app"] == "Pulse").unwrap();
    assert_eq!(pulse.duration, Duration::seconds(1));
    assert_eq!(
        store.get_key_value("settings.capture-after").unwrap(),
        "durable"
    );
    assert_eq!(store.report_library().unwrap().templates[0].name, "Work");
    store.close();
}
