use aw_models::*;
use aw_query::reports::work_report::*;
use chrono::Duration;
use serde_json::Value;
fn vector(name: &str) -> Value {
    let content = match name {
        "daily" => include_str!("../../aw-webui/test/vectors/work-report-v1.json"),
        "periods" => include_str!("../../aw-webui/test/vectors/work-report-periods-v1.json"),
        "insights" => include_str!("../../aw-webui/test/vectors/work-report-insights-v1.json"),
        "timezone" => include_str!("../../aw-webui/test/vectors/work-report-timezone-v1.json"),
        _ => panic!("unknown vector"),
    };
    serde_json::from_str(content).unwrap()
}
fn events(value: &Value, date: &str) -> Vec<Event> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| {
            let timestamp = raw["timestamp"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{date}T08:00:00Z"));
            Event::new(
                timestamp.parse().unwrap(),
                Duration::nanoseconds((raw["duration"].as_f64().unwrap() * 1e9) as i64),
                raw["data"].as_object().cloned().unwrap_or_default(),
            )
        })
        .collect()
}
fn days(value: &Value) -> Vec<ProcessedReportDayV1> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| ProcessedReportDayV1 {
            row: ReportDailyV1 {
                date: raw["date"].as_str().unwrap().into(),
                duration: raw["duration"].as_f64().unwrap(),
                sessions: raw["sessions"].as_u64().unwrap(),
                avg_session: raw["avgSession"].as_f64().unwrap(),
            },
            events: events(&raw["events"], raw["date"].as_str().unwrap()),
        })
        .collect()
}
#[test]
fn report_calculations_daily_and_full_manifest_match_unchanged_free_vector() {
    let v = vector("daily");
    let input = &v["input"];
    let periods = input["periods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|raw| ResolvedPeriodV1 {
            local_date: raw.as_str().unwrap()[..10].into(),
            interval: raw.as_str().unwrap().into(),
        })
        .collect::<Vec<_>>();
    let queried = input["results"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, raw)| ReportQueryDayV1 {
            duration: raw["duration"].as_f64().unwrap(),
            events: events(&raw["events"], &periods[i].local_date),
        })
        .collect();
    let params = ReportParametersV1 {
        host_ids: serde_json::from_value(input["host_ids"].clone()).unwrap(),
        category_paths: serde_json::from_value(input["category_paths"].clone()).unwrap(),
        break_time_seconds: 60,
        date_range: "custom".into(),
        start_of_day: "04:00".into(),
    };
    let (daily, manifest) =
        calculate_daily(&periods, queried, &params, &QueryControl::managed()).unwrap();
    assert_eq!(
        serde_json::to_value(daily.iter().map(|d| &d.row).collect::<Vec<_>>()).unwrap(),
        v["expected"]["daily"]
    );
    assert_eq!(
        serde_json::to_value(manifest).unwrap(),
        v["expected"]["manifest"]
    );
}
#[test]
fn report_calculations_calendar_comparison_and_fields_match_unchanged_free_vector() {
    let v = vector("periods");
    let aggregate = days(&v["input"]["aggregate_days"]);
    let current = days(&v["input"]["current"]);
    let previous = days(&v["input"]["previous"]);
    let control = QueryControl::managed();
    assert_eq!(
        serde_json::to_value(aggregate_days(&aggregate, "week", &control).unwrap()).unwrap(),
        v["expected"]["weekly"]
    );
    assert_eq!(
        serde_json::to_value(aggregate_days(&aggregate, "month", &control).unwrap()).unwrap(),
        v["expected"]["monthly"]
    );
    assert_eq!(
        serde_json::to_value(compare_periods(&current, &previous, &control).unwrap()).unwrap(),
        v["expected"]["comparison"]
    );
    assert_eq!(
        serde_json::to_value(summarize_fields(&current, &control).unwrap()).unwrap(),
        v["expected"]["fields"]
    );
}
#[test]
fn report_calculations_full_metrics_match_unchanged_free_vectors() {
    let v = vector("insights");
    let control = QueryControl::managed();
    assert_eq!(
        serde_json::to_value(focus_blocks(&days(&v["input"]["focus"]), &control).unwrap()).unwrap(),
        v["expected"]["focus"]
    );
    assert_eq!(
        serde_json::to_value(
            context_switches(&days(&v["input"]["context_switches"]), &control).unwrap()
        )
        .unwrap(),
        v["expected"]["context_switches"]
    );
    let paths: Vec<Vec<String>> =
        serde_json::from_value(v["input"]["meetings"]["category_paths"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(
            meeting_load(&days(&v["input"]["meetings"]["daily"]), &paths, &control).unwrap()
        )
        .unwrap(),
        v["expected"]["meetings"]
    );
}
#[test]
fn report_calculations_unknown_metrics_and_output_budget_fail_without_complete_result() {
    let v = vector("insights");
    let control = QueryControl::managed();
    assert_eq!(
        context_switches(&days(&v["input"]["insufficient_context"]), &control)
            .unwrap()
            .outcome,
        ReportMetricOutcomeV1::CouldNotDetermine
    );
    assert_eq!(
        meeting_load(&days(&v["input"]["meetings"]["daily"]), &[], &control)
            .unwrap()
            .outcome,
        ReportMetricOutcomeV1::CouldNotDetermine
    );
    let stopped = QueryControl::managed();
    stopped.charge_bytes(32 * 1024 * 1024).unwrap();
    assert_eq!(
        focus_blocks(&days(&v["input"]["focus"]), &stopped).err(),
        Some(ReportExecutionErrorV1::ByteLimit)
    );
}

fn full_snapshot() -> ReportInputSnapshotV1 {
    let v = vector("daily");
    let input = &v["input"];
    let mut periods = Vec::new();
    let mut inputs = Vec::new();
    for (i, period) in input["periods"].as_array().unwrap().iter().enumerate() {
        let period = ResolvedPeriodV1 {
            local_date: period.as_str().unwrap()[..10].into(),
            interval: period.as_str().unwrap().into(),
        };
        let (start, end) = period.bounds().unwrap();
        let mut window = events(&input["results"][i]["events"], &period.local_date);
        for event in &mut window {
            event.data.insert("app".into(), "Editor".into());
        }
        inputs.push(ReportInputPeriodV1 {
            period: period.clone(),
            buckets: vec![
                ReportInputBucketV1 {
                    bucket_id: "aw-watcher-window_laptop".into(),
                    rows: window.len() as u64,
                    events: window,
                },
                ReportInputBucketV1 {
                    bucket_id: "aw-watcher-afk_laptop".into(),
                    rows: 1,
                    events: vec![Event::new(
                        start,
                        end - start,
                        serde_json::json!({"status":"not-afk"})
                            .as_object()
                            .unwrap()
                            .clone(),
                    )],
                },
            ],
        });
        periods.push(period);
    }
    let template=serde_json::from_value(serde_json::json!({"id":"work","name":"Work","content_version":1,"method_id":"work-time-report","method_version":1,"sections":["daily","weekly","monthly","app-summary","focus-blocks","category-summary"],"category_paths":[["Work"]],"break_time_seconds":60,"rule_pack":null})).unwrap();
    let request = AdvancedReportRunRequestV1 {
        schema_version: 1,
        template_id: "work".into(),
        expected_library_revision: 1,
        ordered_host_ids: vec!["laptop".into()],
        current_periods: periods,
        previous_periods: None,
        timezone: "Europe/Berlin".into(),
        timezone_resolution: "client-local-calendar-v1".into(),
        day_start: "04:00".into(),
    };
    let rule =
        serde_json::from_value(serde_json::json!({"type":"regex","regex":"Editor"})).unwrap();
    ReportInputSnapshotV1 {
        request,
        library_revision: 1,
        template,
        rule_pack: None,
        effective_rules: vec![ReportEffectiveRuleV1 {
            set_id: "default".into(),
            category_path: vec!["Work".into()],
            rule_index: 0,
            rule,
        }],
        sources: vec![ReportSourceV1 {
            host_id: "laptop".into(),
            window_bucket_id: "aw-watcher-window_laptop".into(),
            afk_bucket_id: "aw-watcher-afk_laptop".into(),
        }],
        available_source_buckets: vec![
            "aw-watcher-window_laptop".into(),
            "aw-watcher-afk_laptop".into(),
        ],
        input_periods: inputs,
        captured_at: "2026-06-01T05:00:00Z".parse().unwrap(),
    }
}
#[test]
fn report_calculations_full_native_pipeline_matches_daily_and_pins_frozen_raw_provenance() {
    let snapshot = full_snapshot();
    let control = QueryControl::managed();
    let calculated = aw_query::reports::calculate_report(&snapshot, &control).unwrap();
    let output = serde_json::to_value(&calculated.completed).unwrap();
    let golden = vector("daily");
    assert_eq!(output["daily"], golden["expected"]["daily"]);
    assert_eq!(
        output["calculation_manifest"],
        golden["expected"]["manifest"]
    );
    assert_eq!(
        output["summary"],
        serde_json::json!({"totalDuration":180,"totalSessions":3,"avgSessionLength":60})
    );
    assert_eq!(calculated.completed.source_coverage.source_row_limit, 2000);
    assert_eq!(calculated.completed.source_coverage.report_row_limit, 4000);
    assert_eq!(
        calculated.completed.source_coverage.partial_periods,
        ["2026-06-01"]
    );
    assert!(calculated.completed.raw_events.is_none());
    assert_eq!(calculated.raw_periods.len(), 2);
    assert_eq!(
        calculated.raw_periods[0].buckets[0].events[0].data["app"],
        "Editor"
    );
    assert_eq!(
        output["advanced_report_manifest"]["resolved_request"],
        serde_json::to_value(&snapshot.request).unwrap()
    );
    assert_eq!(
        output["advanced_report_manifest"]["overlap_precedence"],
        "ordered-host-first-source-v1"
    );
    assert_eq!(
        output["advanced_report_manifest"]["label_tie_break"],
        "utf16-code-unit-v1"
    );
    assert_eq!(
        serde_json::to_value(
            calculated
                .completed
                .category_summary
                .as_ref()
                .unwrap()
                .categories
                .clone()
        )
        .unwrap(),
        serde_json::json!([{"category_path":["Work"],"duration":120,"sessions":3}])
    );
    assert_eq!(
        serde_json::to_value(&calculated.completed.field_summaries.app).unwrap(),
        serde_json::json!([{"label":"Editor","duration":120,"sessions":3}])
    );
    calculated.completed.validate().unwrap();
}
#[test]
fn report_calculations_full_native_limits_never_return_a_completed_artifact() {
    let snapshot = full_snapshot();
    let stopped = QueryControl::managed();
    stopped.charge_values(1_000_000).unwrap();
    assert_eq!(
        aw_query::reports::calculate_report(&snapshot, &stopped).err(),
        Some(ReportExecutionErrorV1::ValueLimit)
    );
    for (seed, expected) in [
        (true, ReportExecutionErrorV1::ByteLimit),
        (false, ReportExecutionErrorV1::FuelLimit),
    ] {
        let exhausted = QueryControl::managed();
        if seed {
            exhausted.charge_bytes(32 * 1024 * 1024).unwrap();
        } else {
            exhausted.charge_fuel(5_000_000).unwrap();
        }
        assert_eq!(
            aw_query::reports::calculate_report(&snapshot, &exhausted).err(),
            Some(expected)
        );
    }
    let cancelled = QueryControl::managed();
    cancelled.cancel();
    assert_eq!(
        aw_query::reports::calculate_report(&snapshot, &cancelled).err(),
        Some(ReportExecutionErrorV1::Cancelled)
    );
}
#[test]
fn report_calculations_utf16_field_ties_and_explicit_domain_precedence_match_js() {
    let labels = ["é", "\u{e000}", "😀", "z", "A"];
    let mut day = ProcessedReportDayV1 {
        row: ReportDailyV1 {
            date: "2026-06-01".into(),
            duration: 0.0,
            sessions: 5,
            avg_session: 0.0,
        },
        events: vec![],
    };
    for label in labels {
        day.events.push(Event::new("2026-06-01T12:00:00Z".parse().unwrap(),Duration::seconds(1),serde_json::json!({"app":label,"domain":"","url":"https://private.example/path?token=synthetic"}).as_object().unwrap().clone()));
    }
    let result = summarize_fields(&[day], &QueryControl::managed()).unwrap();
    assert_eq!(
        result
            .app
            .iter()
            .map(|r| r.label.as_str())
            .collect::<Vec<_>>(),
        ["A", "z", "é", "😀", "\u{e000}"]
    );
    assert!(result.domain.is_empty());
}

#[test]
fn report_calculations_js_trim_and_fractional_interval_clipping_preserve_metrics() {
    let day = ProcessedReportDayV1 {
        row: ReportDailyV1 {
            date: "2026-06-01".into(),
            duration: 0.0,
            sessions: 2,
            avg_session: 0.0,
        },
        events: vec![
            Event::new(
                "2026-06-01T09:00:00.000999999Z".parse().unwrap(),
                Duration::nanoseconds(1_000_100),
                serde_json::json!({"app":"\u{feff} Editor \u{feff}"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            Event::new(
                "2026-06-01T09:00:01.001Z".parse().unwrap(),
                Duration::seconds(1),
                serde_json::json!({"app":" Browser "})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        ],
    };
    let result = context_switches(&[day], &QueryControl::managed()).unwrap();
    assert_eq!(result.intervals[0].from_app, "Editor");
    assert_eq!(result.intervals[0].to_app, "Browser");
    assert_eq!(result.intervals[0].start, "2026-06-01T09:00:00.001Z");
    assert_eq!(result.intervals[0].gap_seconds, 1.0);
}
#[test]
fn report_calculations_bridge_uses_immediate_prior_end_and_preserves_offset_dates() {
    let period = ResolvedPeriodV1 {
        local_date: "2026-06-01".into(),
        interval: "2026-06-01T00:00:00+14:00/2026-06-02T00:00:00+14:00".into(),
    };
    let raw = serde_json::json!([{"timestamp":"2026-06-01T00:00:00+14:00","duration":100},{"timestamp":"2026-06-01T00:00:10+14:00","duration":5},{"timestamp":"2026-06-01T00:00:20+14:00","duration":5}]);
    let params = ReportParametersV1 {
        host_ids: vec![],
        category_paths: vec![],
        break_time_seconds: 5,
        date_range: "custom".into(),
        start_of_day: "00:00".into(),
    };
    let (days, _) = calculate_daily(
        &[period],
        vec![ReportQueryDayV1 {
            duration: 110.0,
            events: events(&raw, "2026-06-01"),
        }],
        &params,
        &QueryControl::managed(),
    )
    .unwrap();
    assert_eq!(days[0].row.date, "2026-06-01");
    assert_eq!(days[0].row.duration, 115.0);
}
#[test]
fn report_calculations_dst_and_iso_year_windows_preserve_native_calendar_truth() {
    let v = vector("timezone");
    let periods = v["input"]["periods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| ResolvedPeriodV1 {
            local_date: p.as_str().unwrap()[..10].into(),
            interval: p.as_str().unwrap().into(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        periods
            .iter()
            .map(|p| {
                let (a, b) = p.bounds().unwrap();
                (b - a).num_hours()
            })
            .collect::<Vec<_>>(),
        [23, 24, 25, 24]
    );
    let results = v["input"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| ReportQueryDayV1 {
            duration: r["duration"].as_f64().unwrap(),
            events: vec![],
        })
        .collect();
    let params = ReportParametersV1 {
        host_ids: vec![],
        category_paths: vec![],
        break_time_seconds: 0,
        date_range: "custom".into(),
        start_of_day: "04:00".into(),
    };
    let (daily, _) = calculate_daily(&periods, results, &params, &QueryControl::managed()).unwrap();
    assert_eq!(
        serde_json::to_value(daily.iter().map(|d| &d.row.date).collect::<Vec<_>>()).unwrap(),
        v["expected"]["dates"]
    );
    let input = serde_json::json!([{"date":"2020-12-31","duration":1,"sessions":1,"avgSession":1,"events":[]},{"date":"2021-01-01","duration":1,"sessions":1,"avgSession":1,"events":[]}]);
    let weekly = aggregate_days(&days(&input), "week", &QueryControl::managed()).unwrap();
    assert_eq!(weekly.len(), 1);
    assert_eq!(weekly[0].period, "2020-W53");
}

#[test]
fn report_calculations_category_summary_v1_excludes_bridges_and_orders_utf16_ties() {
    let mut snapshot = full_snapshot();
    snapshot.template.category_paths.clear();
    snapshot.template.break_time_seconds = 60;
    snapshot.effective_rules.clear();
    let labels = ["é", "\u{e000}", "😀", "z", "A"];
    let start = snapshot.input_periods[0].period.bounds().unwrap().0;
    let mut input = Vec::new();
    for (index, label) in labels.iter().enumerate() {
        snapshot.effective_rules.push(ReportEffectiveRuleV1 {
            set_id: "default".into(),
            category_path: vec![(*label).into()],
            rule_index: index as u64,
            rule: serde_json::from_value(
                serde_json::json!({"type":"regex","regex":format!("^{label}$")}),
            )
            .unwrap(),
        });
        input.push(Event::new(
            start + Duration::seconds(index as i64 * 20),
            Duration::seconds(10),
            serde_json::json!({"app":label})
                .as_object()
                .unwrap()
                .clone(),
        ));
    }
    snapshot.input_periods[0].buckets[0].rows = input.len() as u64;
    snapshot.input_periods[0].buckets[0].events = input;
    let result = aw_query::reports::calculate_report(&snapshot, &QueryControl::managed()).unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("vectors/report-category-summary-v1.json")).unwrap();
    assert_eq!(
        serde_json::to_value(result.completed.category_summary.unwrap()).unwrap(),
        expected
    );
    assert_eq!(result.completed.summary.total_duration, 90.0);
}

#[test]
fn report_calculations_host_precedence_keeps_both_raw_sources_and_unknown_skew() {
    for reverse in [false, true] {
        let mut snapshot = full_snapshot();
        snapshot.effective_rules[0].rule.regex = Some("Editor|Browser".into());
        let desktop = ReportSourceV1 {
            host_id: "desktop".into(),
            window_bucket_id: "aw-watcher-window_desktop".into(),
            afk_bucket_id: "aw-watcher-afk_desktop".into(),
        };
        snapshot.available_source_buckets.extend([
            desktop.window_bucket_id.clone(),
            desktop.afk_bucket_id.clone(),
        ]);
        for period in &mut snapshot.input_periods {
            let mut window = period.buckets[0].events.clone();
            for event in &mut window {
                event.data.insert("app".into(), "Browser".into());
            }
            period.buckets.push(ReportInputBucketV1 {
                bucket_id: desktop.window_bucket_id.clone(),
                rows: window.len() as u64,
                events: window,
            });
            let active = period.buckets[1].events.clone();
            period.buckets.push(ReportInputBucketV1 {
                bucket_id: desktop.afk_bucket_id.clone(),
                rows: active.len() as u64,
                events: active,
            });
            if reverse {
                period.buckets.rotate_left(2);
            }
        }
        snapshot.sources.push(desktop);
        snapshot.request.ordered_host_ids.push("desktop".into());
        if reverse {
            snapshot.sources.reverse();
            snapshot.request.ordered_host_ids.reverse();
        }
        let result =
            aw_query::reports::calculate_report(&snapshot, &QueryControl::managed()).unwrap();
        assert_eq!(result.completed.summary.total_duration, 180.0);
        assert_eq!(result.completed.summary.total_sessions, 3);
        assert_eq!(result.completed.field_summaries.app.len(), 1);
        assert_eq!(
            result.completed.field_summaries.app[0].label,
            if reverse { "Browser" } else { "Editor" }
        );
        assert_eq!(result.raw_periods[0].buckets[0].events.len(), 3);
        assert_eq!(result.raw_periods[0].buckets[2].events.len(), 3);
        assert_eq!(
            result.completed.advanced_report_manifest.sources,
            snapshot.sources
        );
        assert_eq!(
            result.completed.source_coverage.clock_skew.status,
            "unknown"
        );
        assert_eq!(
            result
                .completed
                .source_coverage
                .clock_skew
                .correction_bound_seconds,
            0
        );
    }
}
#[test]
fn report_calculations_generated_plan_quotes_unicode_and_never_executes_configuration() {
    let mut snapshot = full_snapshot();
    let host = "Łódź\";return print(42);#\\";
    snapshot.request.ordered_host_ids[0] = host.into();
    snapshot.sources[0].host_id = host.into();
    snapshot.sources[0].window_bucket_id = format!("aw-watcher-window_{host}");
    snapshot.sources[0].afk_bucket_id = format!("aw-watcher-afk_{host}");
    snapshot.available_source_buckets = vec![
        snapshot.sources[0].window_bucket_id.clone(),
        snapshot.sources[0].afk_bucket_id.clone(),
    ];
    for period in &mut snapshot.input_periods {
        period.buckets[0].bucket_id = snapshot.sources[0].window_bucket_id.clone();
        period.buckets[1].bucket_id = snapshot.sources[0].afk_bucket_id.clone();
    }
    let path = vec!["İş \"quoted\" \\ 😀".to_owned()];
    snapshot.template.category_paths = vec![path.clone()];
    snapshot.effective_rules[0].category_path = path.clone();
    let result = aw_query::reports::calculate_report(&snapshot, &QueryControl::managed()).unwrap();
    assert_eq!(result.completed.summary.total_duration, 180.0);
    assert_eq!(
        result.completed.category_summary.unwrap().categories[0].category_path,
        path
    );
    assert_eq!(
        result.raw_periods[0].buckets[0].bucket_id,
        snapshot.sources[0].window_bucket_id
    );
}
#[test]
fn report_calculations_previous_periods_and_raw_order_are_frozen_together() {
    let mut snapshot = full_snapshot();
    let mut previous = full_snapshot().input_periods;
    for period in &mut previous {
        let (start, _) = period.period.bounds().unwrap();
        let prior_start = start - Duration::days(2);
        period.period.local_date = prior_start.format("%Y-%m-%d").to_string();
        period.period.interval = format!(
            "{}/{}",
            prior_start.to_rfc3339(),
            (prior_start + Duration::days(1)).to_rfc3339()
        );
        for bucket in &mut period.buckets {
            for event in &mut bucket.events {
                event.timestamp -= Duration::days(2);
                if bucket.bucket_id.starts_with("aw-watcher-window_") {
                    event.duration = event.duration / 2;
                    event.data.insert("period_marker".into(), "previous".into());
                }
            }
        }
    }
    snapshot.request.previous_periods = Some(previous.iter().map(|p| p.period.clone()).collect());
    snapshot.input_periods.extend(previous);
    snapshot.template.sections.push(ReportSectionV1::Comparison);
    let result = aw_query::reports::calculate_report(&snapshot, &QueryControl::managed()).unwrap();
    let comparison = result.completed.comparison.unwrap();
    assert_eq!(comparison.current.duration, 180.0);
    assert_eq!(comparison.previous.duration, 60.0);
    assert_eq!(comparison.duration_change_percent, Some(200.0));
    assert_eq!(
        result
            .raw_periods
            .iter()
            .map(|p| p.interval.as_str())
            .collect::<Vec<_>>(),
        snapshot
            .input_periods
            .iter()
            .map(|p| p.period.interval.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(result.completed.source_coverage.queried_periods.len(), 4);
}
#[test]
fn report_calculations_rejects_inconsistent_native_completion_and_input() {
    let snapshot = full_snapshot();
    let mut result =
        aw_query::reports::calculate_report(&snapshot, &QueryControl::managed()).unwrap();
    result.completed.summary.total_duration += 1.0;
    assert!(result.completed.validate().is_err());
    let mut snapshot = full_snapshot();
    snapshot.input_periods.pop();
    assert_eq!(
        aw_query::reports::calculate_report(&snapshot, &QueryControl::managed()).err(),
        Some(ReportExecutionErrorV1::DataIntegrity)
    );
}
