use aw_egress::{evaluate, EvaluationContext};
use aw_models::{EgressDecisionV1, EgressOutcomeV1, EgressPolicyV1, EgressReasonCodeV1, EgressRequestV1};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct TestVectors {
    schema_version: u16,
    test_only: bool,
    policy: EgressPolicyV1,
    context: TestContext,
    cases: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestContext {
    local_offset_seconds: i32,
    alias_secret_hex: String,
    preview_id_prefix: String,
}

#[derive(Deserialize)]
struct TestCase {
    id: String,
    request: EgressRequestV1,
    now_utc: String,
    expected: ExpectedDecision,
}

#[derive(Deserialize)]
struct ExpectedDecision {
    outcome: EgressOutcomeV1,
    sanitized_payload: Option<Value>,
    removed_fields: Vec<String>,
    reason_codes: Vec<EgressReasonCodeV1>,
}

fn decode_hex(value: &str) -> Vec<u8> {
    value.as_bytes().chunks_exact(2).map(|pair| {
        let hi = (pair[0] as char).to_digit(16).unwrap();
        let lo = (pair[1] as char).to_digit(16).unwrap();
        ((hi << 4) | lo) as u8
    }).collect()
}

fn vectors() -> TestVectors {
    serde_json::from_str(include_str!("../../test-vectors/privacy-firewall-v1.json")).unwrap()
}

#[test]
fn shared_privacy_firewall_v1_vectors_match() {
    let vectors = vectors();
    assert_eq!(vectors.schema_version, 1);
    assert!(vectors.test_only);
    vectors.policy.validate().unwrap();
    let alias_secret = decode_hex(&vectors.context.alias_secret_hex);

    for case in vectors.cases {
        let now_utc: DateTime<Utc> = DateTime::parse_from_rfc3339(&case.now_utc).unwrap().with_timezone(&Utc);
        let preview_id = format!("{}:{}", vectors.context.preview_id_prefix, case.id);
        let context = EvaluationContext {
            now_utc,
            local_offset_seconds: vectors.context.local_offset_seconds,
            alias_secret: &alias_secret,
            preview_id: &preview_id,
        };
        let decision: EgressDecisionV1 = evaluate(&case.request, &vectors.policy, &context);
        assert_eq!(decision.schema_version, 1, "{}", case.id);
        assert_eq!(decision.policy_version, vectors.policy.version, "{}", case.id);
        assert_eq!(decision.preview_id, preview_id, "{}", case.id);
        assert_eq!(decision.outcome, case.expected.outcome, "{}", case.id);
        assert_eq!(decision.sanitized_payload, case.expected.sanitized_payload, "{}", case.id);
        assert_eq!(decision.removed_fields, case.expected.removed_fields, "{}", case.id);
        assert_eq!(decision.reason_codes, case.expected.reason_codes, "{}", case.id);
    }
}

#[test]
fn stable_alias_is_idempotent_and_never_returns_the_source_path() {
    let vectors = vectors();
    let alias_secret = decode_hex(&vectors.context.alias_secret_hex);
    let preview_id = "vector-preview:alias-idempotence";
    let context = EvaluationContext {
        now_utc: DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc),
        local_offset_seconds: vectors.context.local_offset_seconds,
        alias_secret: &alias_secret,
        preview_id,
    };
    let source_path = "/home/synthetic-user/PeakActivity/plan.md";
    let mut request = EgressRequestV1 {
        schema_version: 1,
        destination_id: "sync-relay".into(),
        purpose_id: "sync".into(),
        retention_id: "test-session".into(),
        payload: serde_json::json!({
            "timestamp": "2026-09-23T12:00:00Z",
            "app": "Editor",
            "document_path": source_path,
        }),
    };
    let first = evaluate(&request, &vectors.policy, &context);
    let first_payload = first.sanitized_payload.clone().unwrap();
    assert_ne!(first_payload["document_path"], source_path);
    request.payload = first_payload.clone();
    let second = evaluate(&request, &vectors.policy, &context);
    assert_eq!(second.sanitized_payload, Some(first_payload));
}

#[test]
fn url_redaction_is_idempotent() {
    let vectors = vectors();
    let alias_secret = decode_hex(&vectors.context.alias_secret_hex);
    let case = vectors.cases.iter().find(|case| case.id == "url-origin-only").unwrap();
    let preview_id = "vector-preview:url-idempotence";
    let context = EvaluationContext {
        now_utc: DateTime::parse_from_rfc3339(&case.now_utc).unwrap().with_timezone(&Utc),
        local_offset_seconds: vectors.context.local_offset_seconds,
        alias_secret: &alias_secret,
        preview_id,
    };
    let first = evaluate(&case.request, &vectors.policy, &context);
    let first_payload = first.sanitized_payload.clone().unwrap();
    let mut second_request = case.request.clone();
    second_request.payload = first_payload.clone();
    let second = evaluate(&second_request, &vectors.policy, &context);
    assert_eq!(second.sanitized_payload, Some(first_payload));
}

#[test]
fn stricter_field_drop_never_adds_payload_data() {
    let vectors = vectors();
    let alias_secret = decode_hex(&vectors.context.alias_secret_hex);
    let case = vectors.cases.iter().find(|case| case.id == "purpose-field-allowlist").unwrap();
    let context = EvaluationContext {
        now_utc: DateTime::parse_from_rfc3339(&case.now_utc).unwrap().with_timezone(&Utc),
        local_offset_seconds: vectors.context.local_offset_seconds,
        alias_secret: &alias_secret,
        preview_id: "vector-preview:monotonicity",
    };
    let baseline = evaluate(&case.request, &vectors.policy, &context)
        .sanitized_payload.unwrap().as_object().unwrap().clone();
    let mut stricter_policy = vectors.policy.clone();
    stricter_policy.user_rules.push(aw_models::EgressRuleV1 {
        pattern: aw_models::EgressPatternV1 {
            kind: aw_models::EgressMatchKindV1::Field,
            value: "/app".into(),
        },
        action: aw_models::EgressRuleActionV1::DropField,
    });
    assert!(stricter_policy.validate().is_ok());
    let stricter = evaluate(&case.request, &stricter_policy, &context)
        .sanitized_payload.unwrap();
    let stricter = stricter.as_object().unwrap();
    assert!(stricter.iter().all(|(key, value)| baseline.get(key) == Some(value)));
    assert!(!stricter.contains_key("app"));
}

#[test]
fn unsupported_hard_deny_version_fails_closed() {
    let vectors = vectors();
    let alias_secret = decode_hex(&vectors.context.alias_secret_hex);
    let case = vectors.cases.iter().find(|case| case.id == "purpose-field-allowlist").unwrap();
    let mut unsupported = vectors.policy;
    unsupported.hard_deny_version = 2;
    let context = EvaluationContext {
        now_utc: DateTime::parse_from_rfc3339(&case.now_utc).unwrap().with_timezone(&Utc),
        local_offset_seconds: vectors.context.local_offset_seconds,
        alias_secret: &alias_secret,
        preview_id: "vector-preview:unsupported-hard-deny",
    };
    let decision = evaluate(&case.request, &unsupported, &context);
    assert_eq!(decision.outcome, EgressOutcomeV1::Deny);
    assert_eq!(decision.reason_codes, vec![EgressReasonCodeV1::InvalidPolicy]);
}
