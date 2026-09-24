use aw_models::{
    calculate_invoice_subtotal_minor, freelancer_report_signature_message_v1,
    round_freelancer_duration,
    ApprovedTimesheetV1, FreelancerCategoryRuleV1, FreelancerProjectV1,
    FreelancerRoundingModeV1, FreelancerWorkspaceV1, InvoiceDraftStatusV1, InvoiceDraftV1,
    InvoiceTaxStatusV1, SignedClientReportV1, FREELANCER_REPORT_SIGNATURE_DOMAIN_V1,
};

fn valid_timesheet() -> ApprovedTimesheetV1 {
    ApprovedTimesheetV1 {
        schema_version: 1,
        project_alias: "project-9af31c".into(),
        date: "2026-09-23".into(),
        approved_duration_seconds: 18_000,
        user_note: Some("Approved sprint work".into()),
    }
}

fn project(alias: &str) -> FreelancerProjectV1 {
    FreelancerProjectV1 {
        project_alias: alias.into(),
        client_alias: Some("client-9af31c".into()),
        label: "Private internal label".into(),
        billable_default: true,
        hourly_rate_minor: Some(7_500),
        hourly_cost_minor: None,
        currency_code: Some("EUR".into()),
        rounding_increment_seconds: 900,
        rounding_mode: FreelancerRoundingModeV1::Nearest,
    }
}

fn workspace() -> FreelancerWorkspaceV1 {
    FreelancerWorkspaceV1 {
        schema_version: 1,
        revision: 4,
        projects: vec![project("project-9af31c")],
        category_rules: vec![FreelancerCategoryRuleV1 {
            category_path: vec!["Work".into(), "Client work".into()],
            project_alias: "project-9af31c".into(),
        }],
    }
}

fn collect_keys(value: &serde_json::Value, keys: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                keys.push(key.clone());
                collect_keys(value, keys);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values { collect_keys(value, keys); }
        }
        _ => {}
    }
}

#[test]
fn approved_timesheet_serialization_contains_only_client_safe_fields() {
    let timesheet = valid_timesheet();
    assert!(timesheet.validate().is_ok());
    let value: serde_json::Value = serde_json::from_slice(&timesheet.artifact_bytes().unwrap()).unwrap();
    let object = value.as_object().unwrap();
    let fields = ["approved_duration_seconds", "date", "project_alias", "schema_version", "user_note"];
    assert_eq!(object.keys().map(String::as_str).collect::<Vec<_>>(), fields);
    for forbidden in ["window_title", "url", "file_path", "event_id", "client_name", "client_alias", "rate_minor", "tax_id", "prompt"] {
        assert!(object.get(forbidden).is_none());
    }
}

#[test]
fn timesheet_contract_rejects_raw_activity_and_unreviewed_financial_fields() {
    let mut value = serde_json::to_value(valid_timesheet()).unwrap();
    value["window_title"] = serde_json::json!("private title marker");
    assert!(serde_json::from_value::<ApprovedTimesheetV1>(value).is_err());

    let mut value = serde_json::to_value(valid_timesheet()).unwrap();
    value["tax_id"] = serde_json::json!("private tax marker");
    assert!(serde_json::from_value::<ApprovedTimesheetV1>(value).is_err());
}

#[test]
fn timesheet_contract_rejects_bad_alias_date_duration_and_note() {
    let mut timesheet = valid_timesheet();
    timesheet.project_alias = "Client Acme".into();
    assert!(timesheet.validate().is_err());

    timesheet = valid_timesheet();
    timesheet.date = "2026-02-30".into();
    assert!(timesheet.validate().is_err());

    timesheet = valid_timesheet();
    timesheet.approved_duration_seconds = 0;
    assert!(timesheet.validate().is_err());
    timesheet.approved_duration_seconds = 86_401;
    assert!(timesheet.validate().is_err());

    timesheet = valid_timesheet();
    timesheet.user_note = Some("x".repeat(1001));
    assert!(timesheet.validate().is_err());
    timesheet.user_note = Some("private\nactivity".into());
    assert!(timesheet.validate().is_err());
}

#[test]
fn timesheet_artifact_bytes_are_compact_and_deterministic() {
    let timesheet = valid_timesheet();
    let first = timesheet.artifact_bytes().unwrap();
    let second = timesheet.artifact_bytes().unwrap();
    assert_eq!(first, second);
    assert_eq!(String::from_utf8(first.clone()).unwrap(),
        r#"{"approved_duration_seconds":18000,"date":"2026-09-23","project_alias":"project-9af31c","schema_version":1,"user_note":"Approved sprint work"}"#);
    assert!(!String::from_utf8(first).unwrap().contains("\n"));
}

#[test]
fn signed_client_report_is_strict_and_uses_a_domain_separated_message() {
    let timesheet = valid_timesheet();
    let report = SignedClientReportV1 {
        schema_version: 1,
        timesheet: timesheet.clone(),
        artifact_sha256: "a".repeat(64),
        signer_public_key_ed25519: "b".repeat(64),
        signature_ed25519: "c".repeat(128),
    };
    assert!(report.validate().is_ok());
    let value = serde_json::to_value(&report).unwrap();
    assert!(value.get("client_alias").is_none());
    assert!(value.get("window_title").is_none());

    let message = freelancer_report_signature_message_v1(&timesheet).unwrap();
    assert!(message.starts_with(FREELANCER_REPORT_SIGNATURE_DOMAIN_V1));
    assert_eq!(
        &message[FREELANCER_REPORT_SIGNATURE_DOMAIN_V1.len()..],
        timesheet.artifact_bytes().unwrap(),
    );

    let mut invalid = report;
    invalid.signature_ed25519 = "not-a-signature".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn generated_freelancer_schema_and_vector_match_the_strict_wire_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!("../../schemas/freelancer-v1.json")).unwrap();
    let mut keys = Vec::new();
    collect_keys(&schema, &mut keys);
    for forbidden in ["window_title", "url", "file_path", "event_id", "client_name", "tax_id", "prompt"] {
        assert!(!keys.iter().any(|key| key == forbidden));
    }
    assert_eq!(schema["oneOf"][0]["additionalProperties"], false);
    assert_eq!(schema["oneOf"][0]["properties"]["project_alias"]["pattern"], "^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$");
    assert_eq!(schema["oneOf"][3]["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["oneOf"][3]["definitions"]["ApprovedTimesheetV1"]["properties"]["schema_version"]["const"], 1);
    assert!(schema["oneOf"][3]["properties"]["signature_ed25519"]["pattern"].is_string());
    let vector: ApprovedTimesheetV1 = serde_json::from_str(include_str!("../../test-vectors/freelancer-timesheet-v1.json")).unwrap();
    assert!(vector.validate().is_ok());
}

#[test]
fn local_project_workspace_has_unique_aliases_and_resolved_category_rules() {
    let mut value = workspace();
    assert!(value.validate().is_ok());

    let mut previous = serde_json::to_value(&value).unwrap();
    previous["projects"][0].as_object_mut().unwrap().remove("client_alias");
    let previous: FreelancerWorkspaceV1 = serde_json::from_value(previous).unwrap();
    assert_eq!(previous.projects[0].client_alias, None);
    assert!(previous.validate().is_ok());

    value.projects.push(project("project-9af31c"));
    assert!(value.validate().is_err());

    value = workspace();
    value.category_rules[0].project_alias = "project-missing".into();
    assert!(value.validate().is_err());

    value = workspace();
    value.category_rules.push(value.category_rules[0].clone());
    assert!(value.validate().is_err());

    value = workspace();
    value.projects[0].label = "private\nclient name".into();
    assert!(value.validate().is_err());

    value = workspace();
    value.projects[0].client_alias = Some("Client Name".into());
    assert!(value.validate().is_err());

    value = workspace();
    value.projects[0].hourly_rate_minor = None;
    value.projects[0].hourly_cost_minor = Some(2_500);
    assert!(value.validate().is_ok());
    value.projects[0].currency_code = None;
    assert!(value.validate().is_err());
}

#[test]
fn timesheet_rounding_and_invoice_minor_units_are_integer_and_bounded() {
    assert_eq!(round_freelancer_duration(1_000, 900, FreelancerRoundingModeV1::Nearest).unwrap(), 900);
    assert_eq!(round_freelancer_duration(1_350, 900, FreelancerRoundingModeV1::Nearest).unwrap(), 1_800);
    assert_eq!(round_freelancer_duration(1_001, 900, FreelancerRoundingModeV1::Down).unwrap(), 900);
    assert_eq!(round_freelancer_duration(1_001, 900, FreelancerRoundingModeV1::Up).unwrap(), 1_800);
    assert!(round_freelancer_duration(86_001, 1_000, FreelancerRoundingModeV1::Up).is_err());
    assert!(round_freelancer_duration(1, 0, FreelancerRoundingModeV1::Nearest).is_err());
    assert_eq!(round_freelancer_duration(7_321, 0, FreelancerRoundingModeV1::None).unwrap(), 7_321);
    assert_eq!(calculate_invoice_subtotal_minor(7_500, 1_800).unwrap(), 3_750);
    assert_eq!(calculate_invoice_subtotal_minor(1, 1_800).unwrap(), 1);
    assert!(calculate_invoice_subtotal_minor(9_007_199_254_740_992, 3_600).is_err());
    assert!(calculate_invoice_subtotal_minor(u64::MAX, 86_400).is_err());
}

#[test]
fn invoice_draft_is_explicitly_non_tax_and_contains_no_client_or_tax_fields() {
    let invoice = InvoiceDraftV1 {
        schema_version: 1,
        project_alias: "project-9af31c".into(),
        period_start: "2026-09-01".into(),
        period_end: "2026-09-23".into(),
        currency_code: "EUR".into(),
        approved_duration_seconds: 1_800,
        hourly_rate_minor: 7_500,
        subtotal_minor: 3_750,
        status: InvoiceDraftStatusV1::Draft,
        tax_status: InvoiceTaxStatusV1::NotCalculated,
    };
    assert!(invoice.validate().is_ok());
    let value = serde_json::to_value(&invoice).unwrap();
    assert_eq!(value["status"], "draft");
    assert_eq!(value["tax_status"], "not_calculated");
    for forbidden in ["client_name", "address", "tax_id", "tax_rate", "window_title", "url"] {
        assert!(value.get(forbidden).is_none());
    }
    assert_eq!(calculate_invoice_subtotal_minor(
        invoice.hourly_rate_minor, invoice.approved_duration_seconds,
    ).unwrap(), invoice.subtotal_minor);
    let mut invalid_period = invoice.clone();
    invalid_period.period_end = "2026-10-02".into();
    assert!(invalid_period.validate().is_err());
}
