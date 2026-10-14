use aw_models::{
    Event, QueryControl, ReportExecutionErrorV1 as Error, ReportInputBucketV1, ReportInputPeriodV1,
    ReportInputSnapshotV1, TimeInterval,
};
use aw_query::{query_controlled, DataType, FrozenQuerySource};
use chrono::{Duration, Utc};
fn snapshot(id: &str) -> ReportInputSnapshotV1 {
    let interval = "2026-01-01T01:00:00+01:00/2026-01-02T01:00:00+01:00";
    let request=serde_json::from_value(serde_json::json!({"schema_version":1,"template_id":"work","expected_library_revision":1,"ordered_host_ids":["Host"],
        "current_periods":[{"local_date":"2026-01-01","interval":interval}],"previous_periods":null,"timezone":"Europe/Berlin","timezone_resolution":"client-local-calendar-v1","day_start":"01:00"})).unwrap();
    let period =
        serde_json::from_value(serde_json::json!({"local_date":"2026-01-01","interval":interval}))
            .unwrap();
    let template=serde_json::from_value(serde_json::json!({"id":"work","name":"Work","content_version":1,"method_id":"work-time-report","method_version":1,
        "sections":["daily"],"category_paths":[],"break_time_seconds":60,"rule_pack":null})).unwrap();
    ReportInputSnapshotV1 {
        request,
        library_revision: 1,
        template,
        rule_pack: None,
        effective_rules: vec![],
        sources: vec![],
        available_source_buckets: vec![id.into()],
        input_periods: vec![ReportInputPeriodV1 {
            period,
            buckets: vec![ReportInputBucketV1 {
                bucket_id: id.into(),
                rows: 1,
                events: vec![Event::new(
                    "2026-01-01T12:00:00Z".parse().unwrap(),
                    Duration::seconds(60),
                    serde_json::json!({"app":"Frozen"})
                        .as_object()
                        .unwrap()
                        .clone(),
                )],
            }],
        }],
        captured_at: Utc::now(),
    }
}
fn run(code: &str, control: &QueryControl) -> Result<DataType, Error> {
    let snapshot = snapshot("window");
    let source = FrozenQuerySource::new(&snapshot);
    query_controlled(
        code,
        &TimeInterval::new_from_string(&snapshot.request.current_periods[0].interval).unwrap(),
        &source,
        control,
    )
}

#[test]
fn report_query_literals_and_legacy_operator_order_are_preserved() {
    let legacy = aw_datastore::Datastore::new_in_memory(false);
    assert_eq!(
        aw_query::query(
            "return 1 + 2 * 3;",
            &TimeInterval::new_from_string("2026-01-01T00:00:00Z/2026-01-02T00:00:00Z").unwrap(),
            &legacy
        )
        .unwrap(),
        DataType::Number(9.0)
    );
    legacy.close();
    assert_eq!(
        run("return 1 + 2 * 3;", &QueryControl::managed()).unwrap(),
        DataType::Number(9.0)
    );
    assert_eq!(
        run("x = [1,2]; return x + [3];", &QueryControl::managed()).unwrap(),
        DataType::List(vec![
            DataType::Number(1.0),
            DataType::Number(2.0),
            DataType::Number(3.0)
        ])
    );
}

#[test]
fn report_query_frozen_source_roundtrips_quoted_backslash_unicode_and_offsets() {
    let name = "aw-window_Łódź\\\";return print(42);#";
    let snapshot = snapshot(name);
    let source = FrozenQuerySource::new(&snapshot);
    let ti = TimeInterval::new_from_string("2026-01-01T00:00:00Z/2026-01-02T00:00:00Z").unwrap();
    let query = format!(
        "return query_bucket({});",
        serde_json::to_string(name).unwrap()
    );
    let result = query_controlled(&query, &ti, &source, &QueryControl::managed()).unwrap();
    let DataType::List(events) = result else {
        panic!("expected frozen events");
    };
    assert_eq!(events.len(), 1);
    let DataType::Event(event) = &events[0] else {
        panic!("expected event");
    };
    assert_eq!(event.data["app"], "Frozen");
    assert_eq!(
        run(
            "return query_bucket(\"missing\");",
            &QueryControl::managed()
        )
        .err(),
        Some(Error::SourceUnavailable)
    );
    let missing =
        TimeInterval::new_from_string("2026-01-03T00:00:00Z/2026-01-04T00:00:00Z").unwrap();
    assert_eq!(
        query_controlled(&query, &missing, &source, &QueryControl::managed()).err(),
        Some(Error::SourceUnavailable)
    );
}

#[test]
fn report_query_rejects_legacy_function_pointers_and_invalid_remainders() {
    for query in [
        "return print(1);",
        "return nonexistent();",
        "return query_bucket;",
        "return [query_bucket];",
        "return {\"fun\":query_bucket};",
        "return 1; @",
    ] {
        assert_eq!(
            run(query, &QueryControl::managed()).err(),
            Some(Error::InternalError),
            "{query}"
        );
    }
}

#[test]
fn report_query_rejects_text_and_ast_caps_before_deep_construction() {
    assert_eq!(
        run(&" ".repeat(65537), &QueryControl::managed()).err(),
        Some(Error::ByteLimit)
    );
    let nested = format!("return {}1{};", "[".repeat(65), "]".repeat(65));
    assert_eq!(
        run(&nested, &QueryControl::managed()).err(),
        Some(Error::ValueLimit)
    );
    let left_deep = format!("return {};", vec!["1"; 66].join("+"));
    assert_eq!(
        run(&left_deep, &QueryControl::managed()).err(),
        Some(Error::ValueLimit)
    );
}

#[test]
fn report_query_flat_collections_do_not_fake_ast_depth() {
    let query = format!("return [{}];", vec!["1"; 100].join(","));
    let DataType::List(result) = run(&query, &QueryControl::managed()).unwrap() else {
        panic!("expected list");
    };
    assert_eq!(result.len(), 100);
}

#[test]
fn report_query_shared_admission_covers_lexing_variables_and_concatenation() {
    let exhausted = QueryControl::managed();
    exhausted.charge_bytes(32 * 1024 * 1024).unwrap();
    assert_eq!(
        run("return \"owned\";", &exhausted).err(),
        Some(Error::ByteLimit)
    );
    let exhausted = QueryControl::managed();
    exhausted.charge_values(1_000_000).unwrap();
    assert_eq!(
        run("return [1];", &exhausted).err(),
        Some(Error::ValueLimit)
    );
    let growth = QueryControl::managed();
    let code = "a=\"Łódź\";a=a+a;a=a+a;return a;";
    assert_eq!(
        run(code, &growth).unwrap(),
        DataType::String("Łódź".repeat(4))
    );
    assert!(growth.stats().bytes > code.len() as u64);
    assert!(growth.stats().values > 10);
    let cancel = QueryControl::managed();
    cancel.cancel();
    assert_eq!(run("return 1;", &cancel).err(), Some(Error::Cancelled));
}

#[test]
fn report_query_controlled_dispatch_preserves_processed_stream_duration_and_rules() {
    let code = r#"events=flood(query_bucket("window"));events=filter_keyvals(events,"app",["Frozen"]);events=categorize(events,[[["Work"],{"type":"regex","regex":"Frozen"}]]);return {"count":event_count(events),"duration":sum_durations(events),"events":events};"#;
    let DataType::Dict(result) = run(code, &QueryControl::managed()).unwrap() else {
        panic!("expected native result");
    };
    assert_eq!(result["count"], DataType::Number(1.0));
    assert_eq!(result["duration"], DataType::Number(60.0));
    let DataType::List(events) = &result["events"] else {
        panic!("expected events");
    };
    let DataType::Event(event) = &events[0] else {
        panic!("expected event");
    };
    assert_eq!(event.data["$category"], serde_json::json!(["Work"]));
}
#[test]
fn report_query_shared_parser_scope_restores_free_behavior_after_limit() {
    let deep = format!("return {}1{};", "[".repeat(65), "]".repeat(65));
    assert_eq!(
        run(&deep, &QueryControl::managed()).err(),
        Some(Error::ValueLimit)
    );
    let store = aw_datastore::Datastore::new_in_memory(false);
    let ti = TimeInterval::new_from_string("2026-01-01T00:00:00Z/2026-01-02T00:00:00Z").unwrap();
    assert!(aw_query::query(&deep, &ti, &store).is_ok());
    store.close();
    assert_eq!(
        run(
            "if false {x=1;} elif false {x=2;} else {x=3;} return x;",
            &QueryControl::managed()
        )
        .unwrap(),
        DataType::Number(3.0)
    );
    assert_eq!(
        run("RETURN=42;", &QueryControl::managed()).unwrap(),
        DataType::Number(42.0)
    );
}
#[test]
fn report_query_frozen_events_survive_actual_live_correction_and_lock() {
    let store = aw_datastore::Datastore::new_in_memory(false);
    let mut captured = snapshot("window");
    store
        .create_bucket(&aw_models::Bucket {
            bid: None,
            id: "window".into(),
            _type: "currentwindow".into(),
            client: "test".into(),
            hostname: "Host".into(),
            created: None,
            data: Default::default(),
            metadata: Default::default(),
            events: None,
            last_updated: None,
        })
        .unwrap();
    let old = captured.input_periods[0].buckets[0].events[0].clone();
    let saved = store.insert_events("window", &[old]).unwrap();
    captured.input_periods[0].buckets[0].events = saved.clone();
    let mut corrected = saved[0].clone();
    corrected.data.insert("app".into(), "Changed".into());
    store.correct_event("window", corrected).unwrap();
    store.lock().unwrap();
    let ti = TimeInterval::new_from_string(&captured.request.current_periods[0].interval).unwrap();
    let source = FrozenQuerySource::new(&captured);
    let DataType::List(result) = query_controlled(
        "return query_bucket(\"window\");",
        &ti,
        &source,
        &QueryControl::managed(),
    )
    .unwrap() else {
        panic!("expected frozen events");
    };
    let DataType::Event(event) = &result[0] else {
        panic!("expected event");
    };
    assert_eq!(event.data["app"], "Frozen");
    store.close();
}

#[test]
fn report_query_owned_conversions_reject_invalid_numbers_shapes_and_rule_fields() {
    for code in [
        r#"return query_bucket("window",1.5);"#,
        r#"return query_bucket("window",0-1);"#,
        r#"return event_count([1]);"#,
        r#"return categorize(query_bucket("window"),[[["Work"],{"type":"regex","regex":"Frozen","script":"bad"}]]);"#,
        r#"return sum_durations("wrong");"#,
    ] {
        assert_eq!(
            run(code, &QueryControl::managed()).err(),
            Some(Error::InternalError)
        );
    }
    let DataType::List(events)=run(r#"return categorize_explained(query_bucket("window"),[[["Work"],{"type":"regex","regex":"Frozen"}]]);"#,&QueryControl::managed()).unwrap() else {panic!("expected events");};
    let DataType::Event(event) = &events[0] else {
        panic!("expected event");
    };
    assert_eq!(
        event.data["$category_trace"]["selected_category"],
        serde_json::json!(["Work"])
    );
}
#[test]
fn report_query_regex_cache_and_budget_are_shared_across_frozen_periods() {
    let mut frozen = snapshot("window");
    let first = TimeInterval::new_from_string(&frozen.request.current_periods[0].interval).unwrap();
    let period:aw_models::ResolvedPeriodV1=serde_json::from_value(serde_json::json!({"local_date":"2026-01-02","interval":"2026-01-02T01:00:00+01:00/2026-01-03T01:00:00+01:00"})).unwrap();
    let second = TimeInterval::new_from_string(&period.interval).unwrap();
    let mut event = frozen.input_periods[0].buckets[0].events[0].clone();
    event.timestamp += Duration::days(1);
    frozen.request.current_periods.push(period.clone());
    frozen.input_periods.push(ReportInputPeriodV1 {
        period,
        buckets: vec![ReportInputBucketV1 {
            bucket_id: "window".into(),
            rows: 1,
            events: vec![event],
        }],
    });
    let source = FrozenQuerySource::new(&frozen);
    let control = QueryControl::managed();
    let code = r#"return event_count(categorize(query_bucket("window"),[[["Work"],{"type":"regex","regex":"Frozen"}]]));"#;
    assert_eq!(
        query_controlled(code, &first, &source, &control).unwrap(),
        DataType::Number(1.0)
    );
    let after_first = control.stats().bytes;
    assert_eq!(
        query_controlled(code, &second, &source, &control).unwrap(),
        DataType::Number(1.0)
    );
    assert!(control.stats().bytes > after_first);
    assert!(
        control.stats().bytes - after_first < 64 * 1024,
        "second period must reuse the bounded run cache"
    );
}
#[test]
fn report_query_cancellation_is_observed_during_actual_owned_work() {
    use std::{sync::Arc, time::Instant};
    let code = format!(
        "a=[{}];{}return a;",
        vec!["1"; 3500].join(","),
        "a=a+a;".repeat(10)
    );
    let control = Arc::new(QueryControl::managed());
    let worker_control = control.clone();
    let worker = std::thread::spawn(move || run(&code, &worker_control));
    let timeout = Instant::now() + std::time::Duration::from_secs(5);
    while control.stats().fuel < 5000 {
        assert!(!worker.is_finished());
        assert!(Instant::now() < timeout);
        std::thread::yield_now();
    }
    control.cancel();
    assert_eq!(worker.join().unwrap().err(), Some(Error::Cancelled));
}
