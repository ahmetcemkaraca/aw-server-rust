use aw_models::{Event, QueryControl, ReportExecutionErrorV1 as Error};
use aw_transform::*;
use chrono::Duration;
fn event(offset: i64, length: i64, label: &str) -> Event {
    Event::new(
        "2026-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            + Duration::seconds(offset),
        Duration::seconds(length),
        serde_json::json!({"app":label})
            .as_object()
            .unwrap()
            .clone(),
    )
}
#[test]
fn report_transforms_preserve_stable_sort_flood_intersection_and_grouping() {
    let events = vec![
        event(0, 2, "A"),
        event(4, 2, "B"),
        event(7, 1, "B"),
        event(13, 1, "A"),
    ];
    for control in [QueryControl::unlimited(), QueryControl::managed()] {
        assert_eq!(
            sort_by_timestamp_controlled(events.clone(), &control).unwrap(),
            sort_by_timestamp(events.clone())
        );
        assert_eq!(
            sort_by_duration_controlled(events.clone(), &control).unwrap(),
            sort_by_duration(events.clone())
        );
        assert_eq!(
            flood_controlled(events.clone(), Duration::seconds(5), &control).unwrap(),
            flood(events.clone(), Duration::seconds(5))
        );
        let filters = vec![event(1, 4, "Active"), event(6, 2, "Active")];
        assert_eq!(
            filter_period_intersect_controlled(events.clone(), filters.clone(), &control).unwrap(),
            filter_period_intersect(events.clone(), filters)
        );
        assert_eq!(
            filter_keyvals_controlled(events.clone(), "app", &[serde_json::json!("B")], &control)
                .unwrap(),
            filter_keyvals(events.clone(), "app", &[serde_json::json!("B")])
        );
        assert_eq!(
            exclude_keyvals_controlled(events.clone(), "app", &[serde_json::json!("B")], &control)
                .unwrap(),
            exclude_keyvals(events.clone(), "app", &[serde_json::json!("B")])
        );
        let actual = sort_by_timestamp(
            merge_events_by_keys_controlled(events.clone(), vec!["app".into()], &control).unwrap(),
        );
        assert_eq!(
            actual,
            sort_by_timestamp(merge_events_by_keys(events.clone(), vec!["app".into()]))
        );
    }
}
#[test]
fn report_transform_overlap_matches_unchanged_golden_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../test-vectors/work-report-merge-v1.json")).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        for control in [QueryControl::unlimited(), QueryControl::managed()] {
            let first = serde_json::from_value(case["first"].clone()).unwrap();
            let second = serde_json::from_value(case["second"].clone()).unwrap();
            let actual = union_no_overlap_controlled(first, second, &control).unwrap();
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                case["expected"],
                "{}",
                case["id"]
            );
        }
    }
}
#[test]
fn report_transforms_admit_before_clone_and_propagate_cancel() {
    let control = QueryControl::managed();
    control.charge_bytes(32 * 1024 * 1024).unwrap();
    assert_eq!(
        union_no_overlap_controlled(vec![event(0, 1, "A")], vec![], &control),
        Err(Error::ByteLimit)
    );
    let cancelled = QueryControl::managed();
    cancelled.cancel();
    assert_eq!(
        filter_period_intersect_controlled(vec![], vec![], &cancelled),
        Err(Error::Cancelled)
    );
    assert_eq!(
        flood_controlled(vec![event(0, 1, "A")], Duration::seconds(5), &cancelled),
        Err(Error::Cancelled)
    );
}

#[test]
fn report_category_controlled_trace_matches_unchanged_golden_vectors() {
    use aw_transform::classify::{
        explain_category_controlled, ControlledRegexCacheV1, ControlledRuleV1,
    };
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../test-vectors/categorization-v1.json")).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let event: Event = serde_json::from_value(case["event"].clone()).unwrap();
        let control = QueryControl::managed();
        let rules = case["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| {
                let path = serde_json::from_value(rule["category"].clone()).unwrap();
                let keys = serde_json::from_value(rule["keys"].clone()).unwrap();
                (
                    path,
                    ControlledRuleV1::regex(
                        rule["pattern"].as_str().unwrap().into(),
                        false,
                        Some(keys),
                        &control,
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let actual = explain_category_controlled(
            &event,
            &rules,
            &mut ControlledRegexCacheV1::default(),
            &control,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            case["expected"],
            "{}",
            case["id"]
        );
    }
}
#[test]
fn report_regex_exhaustion_and_malformed_patterns_are_finite_errors() {
    use aw_transform::classify::{ControlledRegexCacheV1, ControlledRuleV1};
    let control = QueryControl::managed();
    let mut cache = ControlledRegexCacheV1::default();
    let mut event = event(0, 1, "A");
    event
        .data
        .insert("app".into(), format!("{}!", "a".repeat(64)).into());
    let rule = ControlledRuleV1::regex(
        "^(a+)+(?=b)$".into(),
        false,
        Some(vec!["app".into()]),
        &control,
    )
    .unwrap();
    // Verify this fixture actually exhausts the installed engine's bounded VM.
    assert!(fancy_regex::RegexBuilder::new("^(a+)+(?=b)$")
        .backtrack_limit(100_000)
        .build()
        .unwrap()
        .is_match(event.data["app"].as_str().unwrap())
        .is_err());
    assert_eq!(
        cache.matches(&rule, &event, &control),
        Err(Error::FuelLimit)
    );
    let malformed = ControlledRuleV1::regex("(".into(), false, None, &control).unwrap();
    assert_eq!(
        cache.matches(&malformed, &event, &control),
        Err(Error::StaleConfiguration)
    );
    assert!(matches!(
        ControlledRuleV1::regex("x".repeat(4097), false, None, &control),
        Err(Error::ByteLimit)
    ));
}
#[test]
fn report_regex_cache_admission_hits_and_churn_share_the_run_budget() {
    use aw_transform::classify::{ControlledRegexCacheV1, ControlledRuleV1};
    let control = QueryControl::managed();
    let mut cache = ControlledRegexCacheV1::default();
    let event = event(0, 1, "Editor");
    let rule =
        ControlledRuleV1::regex("editor".into(), true, Some(vec!["app".into()]), &control).unwrap();
    assert!(cache.matches(&rule, &event, &control).unwrap());
    let bytes = control.stats().bytes;
    assert!(cache.matches(&rule, &event, &control).unwrap());
    assert_eq!(control.stats().bytes, bytes);
    for i in 0..270 {
        let rule = ControlledRuleV1::regex(format!("Literal{i}"), false, None, &control).unwrap();
        cache.matches(&rule, &event, &control).unwrap();
    }
    assert_eq!(cache.len(), 256);
    assert!(control.stats().bytes > bytes);
    let stopped = QueryControl::managed();
    stopped.charge_bytes(32 * 1024 * 1024).unwrap();
    let rule =
        ControlledRuleV1::regex("Fresh".into(), false, None, &QueryControl::managed()).unwrap();
    let mut empty = ControlledRegexCacheV1::default();
    assert_eq!(
        empty.matches(&rule, &event, &stopped),
        Err(Error::ByteLimit)
    );
    assert!(empty.is_empty());
}

#[test]
fn report_regex_native_build_size_limit_is_not_no_match() {
    use aw_transform::classify::{ControlledRegexCacheV1, ControlledRuleV1};
    let control = QueryControl::managed();
    let rule = ControlledRuleV1::regex("x{10000}".into(), false, None, &control).unwrap();
    assert_eq!(
        ControlledRegexCacheV1::default().matches(&rule, &event(0, 1, "Different"), &control),
        Err(Error::ByteLimit)
    );
}

#[test]
fn report_transform_real_mid_loop_cancel_discards_all_partial_output() {
    use std::{sync::Arc, time::Instant};
    let events = vec![event(0, 1, "Actual loop"); 50_000];
    let values = vec![serde_json::json!("No match"); 100];
    let control = Arc::new(QueryControl::managed());
    let worker_control = control.clone();
    let worker = std::thread::spawn(move || {
        filter_keyvals_controlled(events, "app", &values, &worker_control)
    });
    let timeout = Instant::now() + std::time::Duration::from_secs(5);
    while control.stats().fuel < 10_000 {
        assert!(!worker.is_finished(), "loop ended before work was observed");
        assert!(Instant::now() < timeout);
        std::thread::yield_now();
    }
    control.cancel();
    assert_eq!(worker.join().unwrap(), Err(Error::Cancelled));
}
#[test]
fn report_transform_merged_output_cap_is_finite_and_keeps_free_behavior() {
    let first = (0..2001)
        .map(|i| event(i * 2, 1, "First"))
        .collect::<Vec<_>>();
    let second = (0..2000)
        .map(|i| event(i * 2 + 1, 1, "Second"))
        .collect::<Vec<_>>();
    assert_eq!(
        union_no_overlap_controlled(first.clone(), second.clone(), &QueryControl::managed()),
        Err(Error::RowLimit)
    );
    assert_eq!(union_no_overlap(first, second).len(), 4001);
}
