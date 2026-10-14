#![cfg(any(feature = "encryption", feature = "encryption-vendored"))]

use aw_datastore::{is_sync_policy_field_v1, validate_sync_policy_field_v1};
use aw_models::{
    CapturePolicy, SyncCapturePreferencesV1, SyncPolicyContractErrorV1, SyncPolicyValueV1,
};
use chrono::{TimeZone, Utc};
use serde_json::{json, Value};

fn stored(value: Value) -> SyncPolicyValueV1 {
    SyncPolicyValueV1 {
        schema_version: 1,
        present: true,
        value,
    }
}
fn absent() -> SyncPolicyValueV1 {
    SyncPolicyValueV1 {
        schema_version: 1,
        present: false,
        value: Value::Null,
    }
}
fn valid(scope: &str, value: Value) {
    assert_eq!(
        validate_sync_policy_field_v1(scope, &stored(value)),
        Ok(()),
        "{scope}"
    );
}
fn invalid(scope: &str, value: Value) {
    assert_eq!(
        validate_sync_policy_field_v1(scope, &stored(value)),
        Err(SyncPolicyContractErrorV1::Invalid),
        "{scope}"
    );
}
fn capture() -> Value {
    json!({"window":true,"idle":true,"browser":false,"titles":false,"urls":false,"paths":false,"excluded_apps":[],"excluded_domains":[]})
}
fn user_policy() -> Value {
    json!({"schema_version":1,"user_rules":[],"safe_zone_patterns":[],"after_hours":null})
}
fn signed_bundle() -> Value {
    json!({"schema_version":1,"signer_key_id":"synthetic-root","signature":vec![0u8;64],"bundle":{"schema_version":1,"version":1,"hard_deny_version":1,"destinations":[],"purposes":[],"organization_rules":[]}})
}

#[test]
fn portable_scope_is_closed_and_excludes_local_authority_and_runtime() {
    for scope in [
        "settings.devmode",
        "settings.requestTimeout",
        "settings.setupComplete",
        "settings.initialTimestamp",
        "settings.newReleaseCheckData",
        "settings.ai_endpoint",
        "capture.recording",
        "peakactivity.capture_policy",
        "egress.policy",
        "egress.kill_switch",
        "egress.approval_secret",
        "reports.library.v1",
        "sync.enabled",
    ] {
        assert!(!is_sync_policy_field_v1(scope), "{scope}");
        assert!(validate_sync_policy_field_v1(scope, &absent()).is_err());
    }
    let mut wrong = stored(json!("dark"));
    wrong.schema_version = 2;
    assert!(validate_sync_policy_field_v1("settings.theme", &wrong).is_err());
}

#[test]
fn portable_settings_scalars_preserve_actual_valid_preferences() {
    for (scope, value) in [
        ("settings.startOfDay", json!("04:00")),
        ("settings.startOfWeek", json!("Saturday")),
        ("settings.durationDefault", json!("14400")),
        ("settings.durationDefault", json!(900.5)),
        ("settings.useColorFallback", json!(true)),
        ("settings.landingpage", json!("/activity/Łódź/view/custom")),
        ("settings.theme", json!("auto")),
        ("settings.always_active_pattern", json!("(?<=Editor)Code")),
        (
            "settings.ignoredCategorySuggestions",
            json!(["Any phrase", "Łódź"]),
        ),
        ("settings.showYearly", json!(false)),
        ("settings.useMultidevice", json!(true)),
        ("settings.rawRetentionDays", json!(3650)),
        (
            "settings.uncategorizedNotificationData",
            json!({"isEnabled":true,"minTotalSeconds":0.25,"minRatio":0.2}),
        ),
    ] {
        valid(scope, value);
        assert_eq!(validate_sync_policy_field_v1(scope, &absent()), Ok(()));
    }
}

#[test]
fn portable_settings_reject_wrong_types_and_invalid_native_ranges() {
    for (scope, value) in [
        ("settings.startOfDay", json!("24:00")),
        ("settings.startOfDay", json!("4:00")),
        ("settings.startOfWeek", json!("Funday")),
        ("settings.durationDefault", json!(0)),
        ("settings.durationDefault", json!("Infinity")),
        ("settings.useColorFallback", json!(1)),
        ("settings.landingpage", json!("https://example.invalid")),
        ("settings.landingpage", json!("//example.invalid")),
        ("settings.theme", json!("neon")),
        ("settings.always_active_pattern", json!(false)),
        ("settings.rawRetentionDays", json!(3651)),
        ("settings.rawRetentionDays", json!(1.5)),
        (
            "settings.uncategorizedNotificationData",
            json!({"isEnabled":true,"minTotalSeconds":-1,"minRatio":0.5}),
        ),
        (
            "settings.uncategorizedNotificationData",
            json!({"isEnabled":true,"minTotalSeconds":1,"minRatio":1.1}),
        ),
    ] {
        invalid(scope, value);
    }
    invalid("settings.theme", Value::Null);
}

#[test]
fn portable_category_scopes_preserve_null_empty_priority_and_orphans() {
    for scope in [
        "settings.classes",
        "settings.category_sets",
        "settings.active_set_ids",
    ] {
        valid(scope, Value::Null);
        valid(scope, json!([]));
        assert_eq!(validate_sync_policy_field_v1(scope, &absent()), Ok(()));
    }
    valid(
        "settings.active_set_ids",
        json!(["second", "missing", "first", "second"]),
    );
    valid(
        "settings.category_sets",
        json!([{ "id":"Łódź personal rules", "categories":[] },{ "id":"Łódź personal rules", "categories":[] }]),
    );
}

#[test]
fn portable_categories_keep_free_sizes_lookarounds_selection_and_metadata() {
    let name = vec!["Ł".repeat(200); 10];
    let category = json!({"id":-7,"name":name,"rule":{"type":"regex","regex":"(?<=Editor)Code","select_keys":["app","title"],"ignore_case":false},"data":{"score":"high focus","color":"red","extra":{"retained":true}},"name_pretty":"legacy","children":[]});
    valid(
        "settings.classes",
        json!([category.clone(),{"name":[],"rule":{"type":null},"data":null},{"name":[""],"rule":{"type":"regex","regex":""}}]),
    );
    valid(
        "settings.category_sets",
        json!([{ "id":"Long label ".repeat(100), "categories":[category] }]),
    );
    valid(
        "settings.classes",
        json!((0..1001)
            .map(|i| json!({"name":[format!("Rule{i}")],"rule":{"type":"none"}}))
            .collect::<Vec<_>>()),
    );
    valid(
        "settings.classes",
        json!([{ "name":["Long regex"], "rule":{"type":"regex","regex":"x".repeat(5000)} }]),
    );
}

#[test]
fn portable_category_shapes_and_rule_kinds_fail_closed() {
    for value in [
        json!({}),
        json!([{"name":"Work","rule":{"type":"none"}}]),
        json!([{"name":["Work"],"rule":{"type":"script"}}]),
        json!([{"name":["Work"],"rule":{"type":"regex","regex":false}}]),
        json!([{"name":["Work"],"rule":{"type":"regex","regex":"x","ignore_case":"false"}}]),
        json!([{"name":["Work"],"rule":{"type":"regex","regex":"x","select_keys":[]}}]),
    ] {
        invalid("settings.classes", value);
    }
    invalid(
        "settings.category_sets",
        json!([{ "id":"import-only", "name":"Name", "classes":[] }]),
    );
    invalid("settings.active_set_ids", json!([1]));
}

#[test]
fn portable_privacy_reuses_the_active_parser_without_an_invented_rule_cap() {
    let drop = json!({"enabled":true,"bucket_prefix":null,"field":"title","pattern":"private","action":"drop","replacement":null});
    valid("settings.privacy_filters", json!(vec![drop.clone(); 201]));
    valid("settings.privacy_filters", json!([]));
    invalid(
        "settings.privacy_filters",
        json!([{ "enabled":true,"bucket_prefix":null,"field":null,"pattern":"private","action":"drop","replacement":null }]),
    );
    invalid(
        "settings.privacy_filters",
        json!([{ "enabled":true,"bucket_prefix":null,"field":"title","pattern":"(?=private)","action":"drop","replacement":null }]),
    );
    invalid(
        "settings.privacy_filters",
        json!([{ "enabled":true,"bucket_prefix":null,"field":"title","pattern":"private","action":"redact","replacement":"" }]),
    );
    invalid("settings.privacy_filters", Value::Null);
}

#[test]
fn portable_capture_normalizes_exclusions_without_importing_local_runtime() {
    let current = CapturePolicy {
        revision: 42,
        recording: true,
        paused_until: Some(Utc.with_ymd_and_hms(2026, 10, 14, 9, 0, 0).unwrap()),
        effective_from: Utc.with_ymd_and_hms(2026, 10, 14, 8, 0, 0).unwrap(),
        ..CapturePolicy::default()
    };
    let mut value = capture();
    value["excluded_apps"] = json!([" Editor ", "editor"]);
    value["excluded_domains"] = json!(["EXAMPLE.COM."]);
    valid("capture.minimization", value.clone());
    let portable: SyncCapturePreferencesV1 = serde_json::from_value(value).unwrap();
    let applied = portable.apply_to(&current).unwrap();
    assert_eq!(
        (
            applied.revision,
            applied.recording,
            applied.paused_until,
            applied.effective_from
        ),
        (
            current.revision,
            current.recording,
            current.paused_until,
            current.effective_from
        )
    );
    assert_eq!(applied.excluded_apps, vec!["editor"]);
    assert_eq!(applied.excluded_domains, vec!["example.com"]);
    assert_eq!(
        SyncCapturePreferencesV1::from_policy(&applied)
            .apply_to(&current)
            .unwrap(),
        applied
    );
}

#[test]
fn portable_capture_rejects_runtime_fields_and_existing_invalid_exclusions() {
    let mut value = capture();
    value["recording"] = json!(true);
    invalid("capture.minimization", value);
    let mut value = capture();
    value["excluded_apps"] = json!(vec!["Editor"; 201]);
    invalid("capture.minimization", value);
    let mut value = capture();
    value["excluded_domains"] = json!(["example.com/private"]);
    invalid("capture.minimization", value);
    invalid("capture.minimization", Value::Null);
}

#[test]
fn portable_egress_accepts_typed_candidates_without_granting_signature_authority() {
    valid("egress.user_policy", user_policy());
    valid("egress.signed_bundle", signed_bundle());
    let mut value = user_policy();
    value["after_hours"] = json!({"weekdays":[1,1],"start_minute":60,"end_minute":120});
    invalid("egress.user_policy", value);
    let mut value = signed_bundle();
    value["signature"] = json!(vec![0u8; 63]);
    invalid("egress.signed_bundle", value);
    let mut value = signed_bundle();
    value["bundle"]["version"] = json!(0);
    invalid("egress.signed_bundle", value);
    let mut value = signed_bundle();
    value["schema_version"] = json!(2);
    invalid("egress.signed_bundle", value);
    invalid(
        "egress.signed_bundle",
        json!({"schema_version":1,"version":1,"user_rules":[]}),
    );
}

#[test]
fn portable_views_and_saved_queries_preserve_existing_optional_and_legacy_shapes() {
    valid(
        "settings.views",
        json!([{ "id":"custom","name":"Custom","elements":[{"type":"custom_vis","props":{"visname":"viz","title":"Title"}},{"type":"top_bucket_data","size":3,"props":{"bucketId":"host","field":"data","customField":"title"}}] }]),
    );
    valid(
        "settings.saved_queries",
        json!([{ "id":"legacy","name":"Legacy","query_code":"","start_offset":0,"end_offset":-23 },{ "id":"new","name":"New","query_code":"x".repeat(70000),"start_day_offset":-1,"end_day_offset":0,"event_type":"currentwindow" }]),
    );
    valid(
        "settings.views",
        json!(vec![json!({"id":"view","name":"","elements":[]}); 201]),
    );
    invalid(
        "settings.views",
        json!([{ "id":"view","name":"Name","elements":[{"type":"unsupported"}] }]),
    );
    invalid(
        "settings.views",
        json!([{ "id":"view","name":"Name","elements":[{"type":"top_apps","props":[]}] }]),
    );
    invalid(
        "settings.saved_queries",
        json!([{ "id":"q","name":"Q","query_code":1 }]),
    );
}

#[test]
fn shared_portable_shape_vectors_preserve_actual_native_options_and_nested_sequences() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/sync-policy-portable-v1.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let portable: aw_models::SyncPolicyValueV1 =
            serde_json::from_str(case["portable_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            aw_datastore::validate_sync_policy_field_v1(case["field"].as_str().unwrap(), &portable)
                .is_ok(),
            case["accepted"].as_bool().unwrap(),
            "{case}"
        );
    }
}
