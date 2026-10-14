#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]
use aw_datastore::Datastore;
use aw_models::{
    AdvancedReportRunRequestV1, Bucket, Event, QueryControl, ReportExecutionErrorV1 as Error,
    ReportFeatureAccessV1, ReportInputSnapshotV1, ReportLibraryV1, UpdateReportLibraryRequestV1,
};
use chrono::Duration;
use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
struct Access;
impl ReportFeatureAccessV1 for Access {
    fn with_access(
        &self,
        action: Box<dyn FnOnce() -> Result<(), Error> + '_>,
    ) -> Result<(), Error> {
        action()
    }
}
struct Fixture {
    store: Datastore,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "peak-report-inputs-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let store = Datastore::open_encrypted(
            root.join("activity.db").to_string_lossy().into_owned(),
            "b".repeat(64),
        )
        .unwrap();
        for (id, kind) in [
            ("aw-watcher-window_Host", "currentwindow"),
            ("aw-watcher-afk_Host", "afkstatus"),
        ] {
            store
                .create_bucket(&Bucket {
                    bid: None,
                    id: id.into(),
                    _type: kind.into(),
                    client: "input-test".into(),
                    hostname: "metadata is not the host".into(),
                    created: None,
                    data: Default::default(),
                    metadata: Default::default(),
                    events: None,
                    last_updated: None,
                })
                .unwrap();
        }
        let library:ReportLibraryV1=serde_json::from_value(serde_json::json!({"schema_version":1,"revision":0,"rule_packs":[],"templates":[{
            "id":"work","name":"Work","content_version":1,"method_id":"work-time-report","method_version":1,
            "sections":["daily"],"category_paths":[],"break_time_seconds":60,"rule_pack":null}]})).unwrap();
        store
            .update_report_library(
                UpdateReportLibraryRequestV1 {
                    schema_version: 1,
                    expected_revision: 0,
                    library,
                },
                Arc::new(Access),
            )
            .unwrap();
        store.set_key_value("settings.classes", "[]").unwrap();
        Self { store, root }
    }
    fn open(&self) -> Datastore {
        Datastore::open_encrypted(
            self.root.join("activity.db").to_string_lossy().into_owned(),
            "b".repeat(64),
        )
        .unwrap()
    }
    fn setup(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(self.root.join("activity.db")).unwrap();
        conn.pragma_update(None, "key", "b".repeat(64)).unwrap();
        conn
    }
    fn inputs(
        &self,
        request: AdvancedReportRunRequestV1,
        control: Arc<QueryControl>,
    ) -> Result<Arc<ReportInputSnapshotV1>, Error> {
        self.store
            .read_report_inputs(request, control, Arc::new(Access))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.store.close();
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn request() -> AdvancedReportRunRequestV1 {
    serde_json::from_value(serde_json::json!({"schema_version":1,"template_id":"work","expected_library_revision":1,"ordered_host_ids":["Host"],
        "current_periods":[{"local_date":"2026-01-01","interval":"2026-01-01T00:00:00Z/2026-01-02T00:00:00Z"}],"previous_periods":null,
        "timezone":"Europe/Berlin","timezone_resolution":"client-local-calendar-v1","day_start":"00:00"})).unwrap()
}
fn event(app: &str) -> Event {
    Event::new(
        "2026-01-01T12:00:00Z".parse().unwrap(),
        Duration::seconds(60),
        serde_json::json!({"app":app}).as_object().unwrap().clone(),
    )
}
fn rejected(result: Result<Arc<ReportInputSnapshotV1>, Error>, reason: Error) {
    assert_eq!(result.err(), Some(reason));
}

#[test]
fn report_inputs_freeze_original_data_and_requested_source_order() {
    let f = Fixture::new();
    let saved = f
        .store
        .insert_events("aw-watcher-window_Host", &[event("Old")])
        .unwrap();
    let control = Arc::new(QueryControl::managed());
    let snapshot = f.inputs(request(), control.clone()).unwrap();
    assert_eq!(snapshot.library_revision, 1);
    assert_eq!(snapshot.template.name, "Work");
    assert_eq!(snapshot.sources[0].host_id, "Host");
    assert_eq!(snapshot.input_periods[0].buckets[0].events[0], saved[0]);
    assert_eq!(
        snapshot.available_source_buckets,
        ["aw-watcher-afk_Host", "aw-watcher-window_Host"]
    );
    let mut corrected = saved[0].clone();
    corrected.data.insert("app".into(), "New".into());
    f.store
        .correct_event("aw-watcher-window_Host", corrected)
        .unwrap();
    f.store
        .set_key_value(
            "settings.classes",
            r#"[{"name":["New"],"rule":{"type":"none"}}]"#,
        )
        .unwrap();
    f.store.close();
    assert_eq!(
        snapshot.input_periods[0].buckets[0].events[0].data["app"],
        "Old"
    );
    assert!(snapshot.effective_rules.is_empty());
    assert!(control.stats().execution_ms.is_some());
    assert_eq!(control.stats().rows, 1);
}

#[test]
fn report_inputs_reject_stale_unknown_and_wrong_source_inputs() {
    let f = Fixture::new();
    let mut stale = request();
    stale.expected_library_revision = 0;
    rejected(
        f.inputs(stale, Arc::new(QueryControl::managed())),
        Error::StaleConfiguration,
    );
    let mut unknown = request();
    unknown.ordered_host_ids = vec!["Android-only".into()];
    rejected(
        f.inputs(unknown, Arc::new(QueryControl::managed())),
        Error::SourceUnavailable,
    );
    f.store.delete_bucket("aw-watcher-afk_Host").unwrap();
    rejected(
        f.inputs(request(), Arc::new(QueryControl::managed())),
        Error::SourceUnavailable,
    );
}

#[test]
fn report_inputs_cancel_queued_stage_without_starting_deadline_or_dropping_ack() {
    struct Held {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl ReportFeatureAccessV1 for Held {
        fn with_access(
            &self,
            action: Box<dyn FnOnce() -> Result<(), Error> + '_>,
        ) -> Result<(), Error> {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            action()
        }
    }
    let f = Fixture::new();
    let (entered, wait) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let held = Arc::new(Held {
        entered,
        release: std::sync::Mutex::new(wait_release),
    });
    let store = f.store.clone();
    let first = std::thread::spawn(move || {
        store.read_report_inputs(request(), Arc::new(QueryControl::managed()), held)
    });
    wait.recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    let control = Arc::new(QueryControl::managed());
    let queued_control = control.clone();
    let store = f.store.clone();
    let queued = std::thread::spawn(move || {
        store.read_report_inputs(request(), queued_control, Arc::new(Access))
    });
    assert!(control.stats().execution_ms.is_none());
    control.cancel();
    release.send(()).unwrap();
    first.join().unwrap().unwrap();
    rejected(queued.join().unwrap(), Error::Cancelled);
    assert!(control.stats().execution_ms.is_none());
    f.store
        .set_key_value("settings.after-cancel", "usable")
        .unwrap();
    f.store.force_commit().unwrap();
    assert_eq!(
        f.store.get_key_value("settings.after-cancel").unwrap(),
        "usable"
    );
}

#[test]
fn report_inputs_cap_plus_one_never_returns_partial_complete_input() {
    let f = Fixture::new();
    let events = (0..2001).map(|_| event("Many")).collect::<Vec<_>>();
    f.store
        .insert_events("aw-watcher-window_Host", &events)
        .unwrap();
    rejected(
        f.inputs(request(), Arc::new(QueryControl::managed())),
        Error::RowLimit,
    );
    assert_eq!(
        f.store
            .get_event_count("aw-watcher-window_Host", None, None)
            .unwrap(),
        2001
    );
}

#[test]
fn report_inputs_corrupt_or_oversized_borrowed_payload_has_finite_error() {
    for (raw, reason) in [
        (
            "{\"app\":\"first\",\"app\":\"second\"}".into(),
            Error::DataIntegrity,
        ),
        ("[]".into(), Error::DataIntegrity),
        ("broken".into(), Error::DataIntegrity),
        (
            format!("{{\"padding\":\"{}\"}}", "x".repeat(1024 * 1024)),
            Error::ByteLimit,
        ),
    ] {
        let f = Fixture::new();
        let saved = f
            .store
            .insert_events("aw-watcher-window_Host", &[event("Old")])
            .unwrap();
        f.store.close();
        f.setup()
            .execute(
                "UPDATE events SET data=?1 WHERE id=?2",
                rusqlite::params![raw, saved[0].id.unwrap()],
            )
            .unwrap();
        let store = f.open();
        rejected(
            store.read_report_inputs(
                request(),
                Arc::new(QueryControl::managed()),
                Arc::new(Access),
            ),
            reason,
        );
        store
            .set_key_value("settings.after-corruption", "usable")
            .unwrap();
        store.force_commit().unwrap();
        store.close();
    }
}

#[test]
fn report_inputs_share_value_and_byte_budget_with_frozen_keys() {
    let f = Fixture::new();
    f.store
        .insert_events("aw-watcher-window_Host", &[event("Old")])
        .unwrap();
    for (control, reason) in [
        (QueryControl::managed(), Error::ValueLimit),
        (QueryControl::managed(), Error::ByteLimit),
    ] {
        if reason == Error::ValueLimit {
            control.charge_values(1_000_000).unwrap();
        } else {
            control.charge_bytes(32 * 1024 * 1024).unwrap();
        }
        rejected(f.inputs(request(), Arc::new(control)), reason);
    }
}

#[test]
fn report_inputs_interrupt_actual_pre_row_sql_scan_and_clear_handler() {
    use std::time::Instant;
    let f = Fixture::new();
    f.store.close();
    {
        let mut conn = f.setup();
        let tx = conn.transaction().unwrap();
        let bid: i64 = tx
            .query_row(
                "SELECT id FROM buckets WHERE name='aw-watcher-window_Host'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO events(bucketrow,starttime,endtime,data) VALUES(?1,?2,?3,'{}')",
                )
                .unwrap();
            for i in 0..100_000i64 {
                insert
                    .execute(rusqlite::params![bid, i * 1000, i * 1000 + 1])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
        let query_plan:Vec<String>=conn.prepare("EXPLAIN QUERY PLAN SELECT id,starttime,endtime,data FROM events WHERE bucketrow=?1 AND endtime>=?2 AND starttime<=?3 ORDER BY starttime DESC,id DESC LIMIT ?4").unwrap()
            .query_map(rusqlite::params![bid,1767225600000000000i64,1767312000000000000i64,2001],|r|r.get(3)).unwrap().map(Result::unwrap).collect();
        assert!(
            query_plan
                .iter()
                .any(|s| s.contains("events_bucketrow_starttime_endtime_index")
                    && s.contains("starttime<?")),
            "{query_plan:?}"
        );
    }
    let store = f.open();
    let read_store = store.clone();
    let control = Arc::new(QueryControl::managed());
    let read_control = control.clone();
    let read = std::thread::spawn(move || {
        read_store.read_report_inputs(request(), read_control, Arc::new(Access))
    });
    let timeout = Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let stats = control.stats();
        if stats.fuel >= 3000 && stats.rows == 0 {
            println!(
                "actual pre-row SQL observed before cancel: fuel={} rows={}",
                stats.fuel, stats.rows
            );
            break;
        }
        assert!(
            !read.is_finished(),
            "SQL scan completed before real pre-row work was observed"
        );
        assert!(
            Instant::now() < timeout,
            "SQL scan never reached the observation threshold"
        );
        std::thread::yield_now();
    }
    control.cancel();
    rejected(read.join().unwrap(), Error::Cancelled);
    assert_eq!(control.stats().rows, 0);
    let (start, end) = request().current_periods[0].bounds().unwrap();
    assert!(
        store
            .get_events("aw-watcher-window_Host", Some(start), Some(end), None)
            .unwrap()
            .is_empty(),
        "ordinary long SQL must not inherit the cancelled handler"
    );
    let fuel = Arc::new(QueryControl::managed());
    fuel.charge_fuel(4_998_000).unwrap();
    rejected(
        store.read_report_inputs(request(), fuel, Arc::new(Access)),
        Error::FuelLimit,
    );
    assert!(store
        .get_events("aw-watcher-window_Host", Some(start), Some(end), None)
        .unwrap()
        .is_empty());
    let one = Arc::new(QueryControl::managed());
    store
        .read_report_inputs(request(), one.clone(), Arc::new(Access))
        .unwrap();
    let mut two_periods = request();
    two_periods.current_periods.push(serde_json::from_value(serde_json::json!({"local_date":"2026-01-02","interval":"2026-01-02T00:00:00Z/2026-01-03T00:00:00Z"})).unwrap());
    let two = Arc::new(QueryControl::managed());
    store
        .read_report_inputs(two_periods, two.clone(), Arc::new(Access))
        .unwrap();
    assert!(one.stats().fuel > 1000);
    assert!(two.stats().fuel > one.stats().fuel * 18 / 10);
    println!(
        "shared actual SQL fuel across one/two periods: {}/{}",
        one.stats().fuel,
        two.stats().fuel
    );
    store
        .set_key_value("settings.after-real-sql-cancel", "usable")
        .unwrap();
    store.force_commit().unwrap();
    assert_eq!(
        store
            .get_key_value("settings.after-real-sql-cancel")
            .unwrap(),
        "usable"
    );
    store.close();
}

#[test]
fn report_inputs_unlimited_control_cannot_override_managed_profile() {
    let f = Fixture::new();
    rejected(
        f.inputs(request(), Arc::new(QueryControl::unlimited())),
        Error::StaleConfiguration,
    );
}

#[test]
fn report_inputs_signed_fractional_minimum_timestamps_and_overflow_are_checked() {
    for (start, end) in [(-500_000_000i64, -1i64), (i64::MIN, i64::MIN + 1)] {
        let f = Fixture::new();
        let saved = f
            .store
            .insert_events("aw-watcher-window_Host", &[event("Old")])
            .unwrap();
        f.store.close();
        f.setup()
            .execute(
                "UPDATE events SET starttime=?1,endtime=?2 WHERE id=?3",
                rusqlite::params![start, end, saved[0].id.unwrap()],
            )
            .unwrap();
        let mut req = request();
        let a = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(start);
        let b = a + Duration::seconds(1);
        req.current_periods[0].local_date = a.format("%Y-%m-%d").to_string();
        req.current_periods[0].interval = format!("{}/{}", a.to_rfc3339(), b.to_rfc3339());
        let store = f.open();
        let result = store
            .read_report_inputs(req, Arc::new(QueryControl::managed()), Arc::new(Access))
            .unwrap();
        assert_eq!(result.input_periods[0].buckets[0].events[0].timestamp, a);
        assert_eq!(
            result.input_periods[0].buckets[0].events[0].duration,
            Duration::nanoseconds(end - start)
        );
        store.close();
    }
    for (start, end) in [
        (i64::MIN, i64::MAX),
        (1767268800000000000, 1767232800000000000),
    ] {
        let f = Fixture::new();
        let saved = f
            .store
            .insert_events("aw-watcher-window_Host", &[event("Old")])
            .unwrap();
        f.store.close();
        f.setup()
            .execute(
                "UPDATE events SET starttime=?1,endtime=?2 WHERE id=?3",
                rusqlite::params![start, end, saved[0].id.unwrap()],
            )
            .unwrap();
        let store = f.open();
        rejected(
            store.read_report_inputs(
                request(),
                Arc::new(QueryControl::managed()),
                Arc::new(Access),
            ),
            Error::DataIntegrity,
        );
        store.close();
    }
}

#[test]
fn report_inputs_pinned_rules_fail_on_changed_missing_or_unsupported_categories() {
    let f = Fixture::new();
    let categories = serde_json::json!([{"name":["Old"],"rule":{"type":"regex","regex":"Old"}}]);
    f.store
        .set_key_value(
            "settings.category_sets",
            &serde_json::json!([{"id":"Łódź Work","categories":categories}]).to_string(),
        )
        .unwrap();
    let hash = aw_datastore::report_calculation_sha256(
        &serde_json::from_value::<Vec<aw_models::ReportCategoryV1>>(categories).unwrap(),
    )
    .unwrap();
    let mut library = f.store.report_library().unwrap();
    library.rule_packs=serde_json::from_value(serde_json::json!([{"id":"pinned","name":"Pinned","content_version":1,"category_sets":[{"id":"Łódź Work","calculation_sha256":hash}]}])).unwrap();
    library.templates[0].content_version = 2;
    library.templates[0].rule_pack =
        serde_json::from_value(serde_json::json!({"id":"pinned","content_version":1})).unwrap();
    f.store
        .update_report_library(
            UpdateReportLibraryRequestV1 {
                schema_version: 1,
                expected_revision: 1,
                library,
            },
            Arc::new(Access),
        )
        .unwrap();
    let mut req = request();
    req.expected_library_revision = 2;
    assert_eq!(
        f.inputs(req.clone(), Arc::new(QueryControl::managed()))
            .unwrap()
            .effective_rules[0]
            .set_id,
        "Łódź Work"
    );
    for raw in [
        r#"[{"id":"Łódź Work","categories":[{"name":["New"],"rule":{"type":"regex","regex":"New"}}]}]"#,
        "[]",
        r#"[{"id":"Łódź Work","categories":[{"name":["Old"],"rule":{"type":"script"}}]}]"#,
    ] {
        f.store
            .set_key_value("settings.category_sets", raw)
            .unwrap();
        rejected(
            f.inputs(req.clone(), Arc::new(QueryControl::managed())),
            Error::StaleConfiguration,
        );
    }
}

#[test]
fn report_inputs_actual_concurrent_commit_cannot_mix_keys_and_later_source_rows() {
    use std::time::Instant;
    let f = Fixture::new();
    f.store
        .set_key_value(
            "settings.classes",
            r#"[{"name":["Old"],"rule":{"type":"regex","regex":"Old"}}]"#,
        )
        .unwrap();
    let mut window = event("Old");
    window
        .data
        .insert("padding".into(), "x".repeat(2048).into());
    f.store
        .insert_events("aw-watcher-window_Host", &vec![window; 1999])
        .unwrap();
    let mut afk = event("Old");
    afk.data = serde_json::json!({"status":"not-afk","marker":"Old"})
        .as_object()
        .unwrap()
        .clone();
    let saved = f
        .store
        .insert_events("aw-watcher-afk_Host", &[afk])
        .unwrap();
    f.store.force_commit().unwrap();
    let mut writer = f.setup();
    let _: i64 = writer
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    let mut next = f.store.report_library().unwrap();
    next.revision = 2;
    next.templates[0].name = "New".into();
    next.templates[0].content_version = 2;
    let library = serde_json::to_string(&next).unwrap();
    let control = Arc::new(QueryControl::managed());
    let read_control = control.clone();
    let read_store = f.store.clone();
    let read = std::thread::spawn(move || {
        read_store.read_report_inputs(request(), read_control, Arc::new(Access))
    });
    let timeout = Instant::now() + std::time::Duration::from_secs(5);
    while control.stats().rows < 10 {
        assert!(!read.is_finished());
        assert!(Instant::now() < timeout);
        std::thread::yield_now();
    }
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "UPDATE key_value SET value=?1 WHERE key='reports.library.v1'",
        [library],
    )
    .unwrap();
    tx.execute(
        "UPDATE key_value SET value=?1 WHERE key='settings.classes'",
        [r#"[{"name":["New"],"rule":{"type":"regex","regex":"New"}}]"#],
    )
    .unwrap();
    tx.execute(
        "UPDATE events SET data=?1 WHERE id=?2",
        rusqlite::params![r#"{"status":"afk","marker":"New"}"#, saved[0].id.unwrap()],
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(
        !read.is_finished(),
        "concurrent commit must occur before snapshot's remaining source reads"
    );
    let captured = read.join().unwrap().unwrap();
    assert_eq!(captured.library_revision, 1);
    assert_eq!(captured.template.name, "Work");
    assert_eq!(captured.effective_rules[0].category_path, ["Old"]);
    assert_eq!(
        captured.input_periods[0].buckets[1].events[0].data["marker"],
        "Old"
    );
    let mut req = request();
    req.expected_library_revision = 2;
    let fresh = f.inputs(req, Arc::new(QueryControl::managed())).unwrap();
    assert_eq!(fresh.template.name, "New");
    assert_eq!(fresh.effective_rules[0].category_path, ["New"]);
    assert_eq!(
        fresh.input_periods[0].buckets[1].events[0].data["marker"],
        "New"
    );
}

#[test]
fn report_inputs_combined_rows_and_fuel_accumulate_across_periods() {
    let f = Fixture::new();
    let mut spanning = event("Old");
    spanning.duration = Duration::days(3);
    f.store
        .insert_events("aw-watcher-window_Host", &[spanning.clone(), spanning])
        .unwrap();
    let mut req = request();
    req.current_periods.push(serde_json::from_value(serde_json::json!({"local_date":"2026-01-02","interval":"2026-01-02T00:00:00Z/2026-01-03T00:00:00Z"})).unwrap());
    let ordinary = Arc::new(QueryControl::managed());
    f.inputs(req.clone(), ordinary.clone()).unwrap();
    assert_eq!(ordinary.stats().rows, 4);
    let boundary = Arc::new(QueryControl::managed());
    boundary.charge_rows(249_997).unwrap();
    rejected(f.inputs(req, boundary.clone()), Error::RowLimit);
    assert_eq!(boundary.stats().rows, 250_000);
    println!(
        "combined row admission retained across periods: {}",
        boundary.stats().rows
    );
}

#[test]
fn report_inputs_require_encrypted_vault_and_reject_bad_resolved_intervals() {
    let plain = Datastore::new_in_memory(false);
    rejected(
        plain.read_report_inputs(
            request(),
            Arc::new(QueryControl::managed()),
            Arc::new(Access),
        ),
        Error::SourceUnavailable,
    );
    plain.close();
    let f = Fixture::new();
    let mut req = request();
    req.current_periods[0].interval = "2026-01-02T00:00:00Z/2026-01-01T00:00:00Z".into();
    rejected(
        f.inputs(req, Arc::new(QueryControl::managed())),
        Error::StaleConfiguration,
    );
}

#[test]
fn report_inputs_reject_oversized_stored_library_before_decoding() {
    let f = Fixture::new();
    f.store.close();
    f.setup()
        .execute(
            "UPDATE key_value SET value=?1 WHERE key='reports.library.v1'",
            [" ".repeat(1024 * 1024 + 1)],
        )
        .unwrap();
    let store = f.open();
    let control = Arc::new(QueryControl::managed());
    rejected(
        store.read_report_inputs(request(), control.clone(), Arc::new(Access)),
        Error::ByteLimit,
    );
    assert!(
        control.stats().bytes < 1024 * 1024,
        "oversized borrowed library must not be admitted/copied"
    );
    store.close();
}

#[test]
fn report_inputs_missing_parent_baseline_and_global_indices_match_free_resolution() {
    let f=Fixture::new();
    f.store.set_key_value("settings.category_sets",r#"[{"id":"first","categories":[{"name":["Work","Code","Editor"],"rule":{"type":"regex","regex":"Editor"}}]},{"id":"second","categories":[{"name":["Play","Game"],"rule":{"type":"none"}}]}]"#).unwrap();
    f.store.set_key_value("settings.active_set_ids",r#"["first","second"]"#).unwrap();
    let captured=f.inputs(request(),Arc::new(QueryControl::managed())).unwrap();
    let paths=captured.effective_rules.iter().map(|r|r.category_path.clone()).collect::<Vec<_>>();
    assert_eq!(paths,vec![vec!["Work","Code","Editor"],vec!["Play","Game"],vec!["Work","Code"],vec!["Work"],vec!["Play"]]);
    assert_eq!(captured.effective_rules.iter().map(|r|r.rule_index).collect::<Vec<_>>(),[0,1,2,3,4]);
    assert_eq!(captured.effective_rules[2].set_id,"first");assert_eq!(captured.effective_rules[4].set_id,"second");
    assert!(captured.effective_rules[2..].iter().all(|r|r.rule.kind==Some(aw_models::ReportRuleTypeV1::None)));
}

#[test]
fn report_inputs_parent_join_collision_and_later_explicit_parent_remain_free_compatible() {
    let f=Fixture::new();
    for (raw,expected) in [
        (r#"[{"name":["Work","Code","Editor"],"rule":{"type":"none"}},{"name":["Work","Code"],"rule":{"type":"regex","regex":"Code"}}]"#,vec![vec!["Work","Code","Editor"],vec!["Work","Code"],vec!["Work"]]),
        (r#"[{"name":["A>B"],"rule":{"type":"none"}},{"name":["A","B","C"],"rule":{"type":"none"}}]"#,vec![vec!["A>B"],vec!["A","B","C"]])
    ] {
        f.store.set_key_value("settings.classes",raw).unwrap();let captured=f.inputs(request(),Arc::new(QueryControl::managed())).unwrap();
        assert_eq!(captured.effective_rules.iter().map(|r|r.category_path.clone()).collect::<Vec<_>>(),expected);
    }
}
