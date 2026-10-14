use aw_models::{
    AdvancedReportRunRequestV1, PortableReportPackV1, ReportCompletedV1, ReportLibraryV1,
    ReportRunStatusV1,
};
use serde_json::{json, Value};

fn library() -> Value {
    json!({"schema_version":1,"revision":0,"templates":[{
        "id":"work","name":"Work","content_version":1,"method_id":"work-time-report",
        "method_version":1,"sections":["daily"],"category_paths":[["Work"]],
        "break_time_seconds":60,"rule_pack":null
    }],"rule_packs":[]})
}

fn request() -> Value {
    json!({"schema_version":1,"template_id":"work","expected_library_revision":1,
        "ordered_host_ids":["laptop"],"current_periods":[{
            "local_date":"2026-03-29",
            "interval":"2026-03-29T04:00:00+02:00/2026-03-30T04:00:00+02:00"
        }],"previous_periods":null,"timezone":"Europe/Berlin",
        "timezone_resolution":"client-local-calendar-v1","day_start":"04:00"})
}

#[test]
fn report_contract_valid_library_and_original_offsets_roundtrip() {
    let lib: ReportLibraryV1 = serde_json::from_value(library()).unwrap();
    lib.validate().unwrap();
    assert_eq!(serde_json::to_value(&lib).unwrap(), library());
    let run: AdvancedReportRunRequestV1 = serde_json::from_value(request()).unwrap();
    run.validate().unwrap();
    assert_eq!(serde_json::to_value(run).unwrap(), request());
}

#[test]
fn report_contract_rejects_positional_duplicate_and_unknown_records() {
    for text in [
        "[]",
        "[1,0,[],[]]",
        r#"{"schema_version":1,"revision":0,"revision":1,"templates":[],"rule_packs":[]}"#,
        r#"{"schema_version":1,"revision":0,"templates":[],"rule_packs":[],"paid":true}"#,
    ] {
        assert!(
            serde_json::from_str::<ReportLibraryV1>(text).is_err(),
            "{text}"
        );
    }
    let mut lib = library();
    lib["templates"][0]["script"] = json!("RETURN = query_bucket('x');");
    assert!(serde_json::from_value::<ReportLibraryV1>(lib).is_err());
    let mut run = request();
    run["current_periods"][0] = json!(["2026-03-29", "x/y"]);
    assert!(serde_json::from_value::<AdvancedReportRunRequestV1>(run).is_err());
}

#[test]
fn report_contract_rejects_invalid_or_unbounded_library_content() {
    for (field, invalid) in [
        ("id", json!("Existing Set Name")),
        ("content_version", json!(0)),
        ("name", json!("é".repeat(41))),
        ("sections", json!(["daily", "daily"])),
        ("sections", json!(["script"])),
        ("break_time_seconds", json!(3601)),
    ] {
        let mut lib = library();
        lib["templates"][0][field] = invalid;
        assert!(
            serde_json::from_value::<ReportLibraryV1>(lib)
                .and_then(|v| v.validate().map_err(serde::de::Error::custom))
                .is_err(),
            "{field}"
        );
    }
    let mut lib = library();
    lib["templates"] = json!(vec![lib["templates"][0].clone(); 101]);
    assert!(serde_json::from_value::<ReportLibraryV1>(lib).is_err());
}

#[test]
fn report_contract_checks_calendar_shapes_without_claiming_iana_validation() {
    for (field, invalid) in [
        ("day_start", json!("24:00")),
        ("day_start", json!("4:00")),
        ("timezone", json!("")),
        ("timezone", json!("a".repeat(129))),
        ("ordered_host_ids", json!(["laptop", "laptop"])),
        ("current_periods", json!([])),
        ("timezone_resolution", json!("server-iana")),
    ] {
        let mut run = request();
        run[field] = invalid;
        assert!(
            serde_json::from_value::<AdvancedReportRunRequestV1>(run)
                .and_then(|v| v.validate().map_err(serde::de::Error::custom))
                .is_err(),
            "{field}"
        );
    }
    let mut run = request();
    run["timezone"] = json!("client label, not an IANA assertion");
    serde_json::from_value::<AdvancedReportRunRequestV1>(run)
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn report_contract_checks_date_interval_order_and_comparison_count() {
    for (field, invalid) in [
        ("local_date", json!("2026-02-30")),
        (
            "interval",
            json!("2026-03-29T04:00:00+02:00/2026-03-29T04:00:00+02:00"),
        ),
        (
            "interval",
            json!("2026-03-30T04:00:00+02:00/2026-03-29T04:00:00+02:00"),
        ),
    ] {
        let mut run = request();
        run["current_periods"][0][field] = invalid;
        assert!(
            serde_json::from_value::<AdvancedReportRunRequestV1>(run)
                .unwrap()
                .validate()
                .is_err(),
            "{field}"
        );
    }
    let mut run = request();
    run["current_periods"] = json!([
        run["current_periods"][0].clone(),
        run["current_periods"][0].clone()
    ]);
    assert!(serde_json::from_value::<AdvancedReportRunRequestV1>(run)
        .unwrap()
        .validate()
        .is_err());
    let mut run = request();
    run["previous_periods"] = json!([]);
    assert!(serde_json::from_value::<AdvancedReportRunRequestV1>(run)
        .unwrap()
        .validate()
        .is_err());
}

#[test]
fn report_contract_nested_collections_reject_before_accepting_the_extra_element() {
    let mut lib = library();
    lib["templates"][0]["category_paths"] = json!([vec!["x"; 9]]);
    assert!(serde_json::from_value::<ReportLibraryV1>(lib).is_err());
    let mut lib = library();
    lib["templates"][0]["category_paths"] = json!([["é".repeat(65)]]);
    assert!(serde_json::from_value::<ReportLibraryV1>(lib).is_err());
    let mut run = request();
    run["ordered_host_ids"] = json!(["a".repeat(129)]);
    assert!(serde_json::from_value::<AdvancedReportRunRequestV1>(run).is_err());
    let mut run = request();
    run["previous_periods"] = json!(vec![run["current_periods"][0].clone(); 187]);
    assert!(serde_json::from_value::<AdvancedReportRunRequestV1>(run).is_err());
}

#[test]
fn report_contract_total_period_cap_and_dst_windows_are_exact() {
    let mut run = request();
    let start = chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    let dates: Vec<Value> = (0..186).map(|n| {
        let date = start + chrono::Duration::days(n);
        let end = date + chrono::Duration::days(1);
        json!({"local_date":date.to_string(),"interval":format!("{date}T04:00:00+00:00/{end}T04:00:00+00:00")})
    }).collect();
    run["current_periods"] = json!(dates);
    serde_json::from_value::<AdvancedReportRunRequestV1>(run.clone())
        .unwrap()
        .validate()
        .unwrap();
    run["previous_periods"] = json!(vec![run["current_periods"][0].clone(); 186]);
    assert!(serde_json::from_value::<AdvancedReportRunRequestV1>(run)
        .unwrap()
        .validate()
        .is_err());
    for interval in [
        "2026-03-28T04:00:00+01:00/2026-03-29T04:00:00+02:00",
        "2026-10-24T04:00:00+02:00/2026-10-25T04:00:00+01:00",
    ] {
        let mut run = request();
        run["current_periods"][0]["local_date"] = json!(&interval[..10]);
        run["current_periods"][0]["interval"] = json!(interval);
        serde_json::from_value::<AdvancedReportRunRequestV1>(run)
            .unwrap()
            .validate()
            .unwrap();
    }
}

#[test]
fn report_contract_existing_set_names_do_not_get_new_record_id_restrictions() {
    let mut lib = library();
    lib["rule_packs"] = json!([{"id":"pack","name":"Pack","content_version":1,
        "category_sets":[{"id":"Łódź personal rules","calculation_sha256":"a".repeat(64)}]}]);
    lib["templates"][0]["rule_pack"] = json!({"id":"pack","content_version":1});
    serde_json::from_value::<ReportLibraryV1>(lib.clone())
        .unwrap()
        .validate()
        .unwrap();
    lib["templates"][0]["rule_pack"]["content_version"] = json!(2);
    assert!(serde_json::from_value::<ReportLibraryV1>(lib)
        .unwrap()
        .validate()
        .is_err());
}

#[test]
fn report_contract_portable_sets_keep_cosmetic_numeric_strings_and_legacy_none() {
    let portable = json!({"schema_version":1,"templates":[],"rule_packs":[],
    "category_sets":[{"id":"Personal rules Łódź","name":"Personal","classes":[
        {"name":["Work"],"rule":{"type":null},"data":{"color":"#abc","score":"42"}}
    ]}]});
    let value: PortableReportPackV1 = serde_json::from_value(portable.clone()).unwrap();
    value.validate().unwrap();
    assert_eq!(serde_json::to_value(value).unwrap(), portable);
    for score in [json!("NaN"), json!("infinity"), json!([])] {
        let mut bad = portable.clone();
        bad["category_sets"][0]["classes"][0]["data"]["score"] = score;
        assert!(serde_json::from_value::<PortableReportPackV1>(bad)
            .and_then(|v| v.validate().map_err(serde::de::Error::custom))
            .is_err());
    }
    let mut bad = portable;
    bad["category_sets"][0]["classes"][0]["rule"]["script"] = json!("run()");
    assert!(serde_json::from_value::<PortableReportPackV1>(bad).is_err());
}

#[test]
fn report_contract_status_never_accepts_complete_without_a_result_or_partial_totals() {
    let status = json!({"schema_version":1,"run_id":"a".repeat(32),"state":"failed",
        "queue_wait_ms":12,"execution_ms":0,"reason":"entitlement-unavailable","result":null});
    let value: ReportRunStatusV1 = serde_json::from_value(status.clone()).unwrap();
    value.validate().unwrap();
    assert_eq!(serde_json::to_value(value).unwrap(), status);
    for (field, bad) in [
        ("state", json!("complete")),
        ("reason", json!("raw exception")),
        ("run_id", json!("path/id")),
    ] {
        let mut changed = status.clone();
        changed[field] = bad;
        assert!(serde_json::from_value::<ReportRunStatusV1>(changed)
            .and_then(|v| v.validate().map_err(serde::de::Error::custom))
            .is_err());
    }
    assert!(
        serde_json::from_str::<ReportRunStatusV1>("[1,\"x\",\"queued\",null,null,null,null]")
            .is_err()
    );
}

fn completed() -> Value {
    let vector: Value = serde_json::from_str(include_str!(
        "../../aw-webui/test/vectors/work-report-v1.json"
    ))
    .unwrap();
    json!({
        "parameters":{"host_ids":["laptop"],"category_paths":[["Work"]],"break_time_seconds":60,"date_range":"custom","start_of_day":"04:00"},
        "calculation_manifest":vector["expected"]["manifest"],
        "source_coverage":{"method_id":"work-report-source-coverage","method_version":1,
            "available_source_buckets":[],"queried_source_buckets":[],"queried_periods":vector["input"]["periods"],
            "partial_periods":[],"limited_periods":[],"source_row_limit":2000,"report_row_limit":4000,
            "timezone":"Europe/Berlin","source_health":"unknown",
            "clock_skew":{"status":"not_applicable","correction_bound_seconds":0,"limitation":"Unknown coverage"}},
        "comparison":null,"weekly":[],"monthly":[],
        "field_summaries":{"method_id":"work-time-field-summary","method_version":1,"project":[],"app":[],"domain":[],"active_away":null},
        "metrics":{"focus_blocks":null,"context_switches":null,"meeting_load":null},
        "summary":{"totalDuration":180,"totalSessions":3,"avgSessionLength":60},"daily":vector["expected"]["daily"],
        "advanced_report_manifest":{"schema_version":1,"library_revision":1,"resolved_request":request(),
            "template":library()["templates"][0],"rule_pack":null,"effective_rules":[],"sources":[],"source_rows":[],
            "snapshot_time":"2026-03-30T00:00:00Z","overlap_precedence":"ordered-host-first-source-v1",
            "label_tie_break":"utf16-code-unit-v1","limits":{"periods":186,"hosts":8,"source_rows":2000,"merged_rows":4000,
                "raw_rows":250000,"bytes":33554432,"values":1000000,"fuel":5000000,"execution_seconds":30,
                "query_bytes":65536,"ast_depth":64,"event_json_bytes":1048576,"regex_bytes":4096,"regex_backtracks":100000,"regex_cache_entries":256}},
        "category_summary":null
    })
}

#[test]
fn report_contract_complete_shape_keeps_free_export_names_and_excludes_raw_by_default() {
    let original = completed();
    let report: ReportCompletedV1 = serde_json::from_value(original.clone()).unwrap();
    report.validate().unwrap();
    assert_eq!(serde_json::to_value(report).unwrap(), original);
    assert!(original.get("rawEvents").is_none());
}

#[test]
fn report_contract_complete_rejects_nested_extra_fields_and_nonfinite_output() {
    let mut bad = completed();
    bad["daily"][0]["events"] = json!([{ "title":"raw" }]);
    assert!(serde_json::from_value::<ReportCompletedV1>(bad).is_err());
    let mut value: ReportCompletedV1 = serde_json::from_value(completed()).unwrap();
    value.summary.total_duration = f64::NAN;
    assert!(value.validate().is_err());
}

#[test]
fn report_contract_protocol_requires_owner_fields_and_redacts_capability_debug() {
    use aw_models::{
        ReportImportCommitRequestV1, ReportRunReadRequestV1, ReportRunStartResponseV1,
    };
    let start = json!({"schema_version":1,"run_id":"a".repeat(32),"capability":"b".repeat(64),"state":"queued"});
    let value: ReportRunStartResponseV1 = serde_json::from_value(start.clone()).unwrap();
    value.validate().unwrap();
    assert!(!format!("{value:?}").contains(&"b".repeat(64)));
    assert_eq!(serde_json::to_value(value).unwrap(), start);
    assert!(serde_json::from_str::<ReportRunReadRequestV1>(
        r#"{"schema_version":1,"run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
    )
    .is_err());
    let commit: ReportImportCommitRequestV1 = serde_json::from_value(
        json!({"schema_version":1,"preview_id":"a".repeat(32),"accept":false}),
    )
    .unwrap();
    assert!(commit.validate().is_err());
    assert!(serde_json::from_value::<ReportImportCommitRequestV1>(
        json!({"schema_version":1,"preview_id":"a".repeat(32),"accept":true,"payload":{}})
    )
    .is_err());
}

#[test]
fn report_contract_raw_projection_is_strict_without_changing_legacy_events() {
    use aw_models::RawReportBucketV1;
    let raw = json!({"bucket_id":"window","events":[{"id":null,"timestamp":"2026-06-01T00:00:00Z","duration":1,
        "data":{"nested":["still allowed"]},"unexpected":"must not be a report field"}]});
    assert!(serde_json::from_value::<RawReportBucketV1>(raw).is_err());
    let legacy: aw_models::Event = serde_json::from_value(
        json!({"timestamp":"2026-06-01T00:00:00Z","data":{},"unexpected":true}),
    )
    .unwrap();
    assert_eq!(legacy.duration, chrono::Duration::zero());
}

#[test]
fn report_contract_comparison_cap_is_not_masked_by_invalid_periods() {
    let start = chrono::NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
    let periods = |first: chrono::NaiveDate, days: i64| {
        (0..days).map(|n| {
        let date=first+chrono::Duration::days(n); let end=date+chrono::Duration::days(1);
        json!({"local_date":date.to_string(),"interval":format!("{date}T04:00:00Z/{end}T04:00:00Z")})
    }).collect::<Vec<_>>()
    };
    for (days, valid) in [(93, true), (94, false)] {
        let mut input = request();
        input["current_periods"] = json!(periods(start, days));
        input["previous_periods"] = json!(periods(start - chrono::Duration::days(days), days));
        assert_eq!(
            serde_json::from_value::<AdvancedReportRunRequestV1>(input)
                .unwrap()
                .validate()
                .is_ok(),
            valid
        );
    }
}
