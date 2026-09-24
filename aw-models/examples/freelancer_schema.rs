use aw_models::{
    ApprovedTimesheetV1, FreelancerWorkspaceV1, InvoiceDraftV1, SignedClientReportV1,
    FREELANCER_MAX_SAFE_MINOR_UNITS_V1,
};
use schemars::{schema_for, JsonSchema};
use serde_json::{json, to_value, Value};

fn schema<T: JsonSchema>() -> Value {
    to_value(schema_for!(T)).unwrap()
}

fn constrain(contract: &mut Value, path: &str, key: &str, value: Value) {
    contract.pointer_mut(path).unwrap()[key] = value;
}

fn main() {
    let mut contract = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "PeakActivity Freelancer Contract V1",
        "oneOf": [
            schema::<ApprovedTimesheetV1>(),
            schema::<FreelancerWorkspaceV1>(),
            schema::<InvoiceDraftV1>(),
            schema::<SignedClientReportV1>(),
        ]
    });
    for schema in contract["oneOf"].as_array_mut().unwrap() {
        if let Some(version) = schema.pointer_mut("/properties/schema_version") {
            *version = json!({"const": 1, "type": "integer"});
        }
    }
    constrain(&mut contract, "/oneOf/3/properties/schema_version", "const", json!(1));
    constrain(&mut contract, "/oneOf/3/definitions/ApprovedTimesheetV1/properties/schema_version", "const", json!(1));
    let aliases = "^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$";
    for path in [
        "/oneOf/0/properties/project_alias",
        "/oneOf/1/definitions/FreelancerProjectV1/properties/project_alias",
        "/oneOf/1/definitions/FreelancerCategoryRuleV1/properties/project_alias",
        "/oneOf/2/properties/project_alias",
        "/oneOf/3/definitions/ApprovedTimesheetV1/properties/project_alias",
    ] {
        constrain(&mut contract, path, "pattern", json!(aliases));
    }
    for path in [
        "/oneOf/0/properties/date",
        "/oneOf/2/properties/period_start",
        "/oneOf/2/properties/period_end",
        "/oneOf/3/definitions/ApprovedTimesheetV1/properties/date",
    ] {
        constrain(&mut contract, path, "format", json!("date"));
        constrain(&mut contract, path, "pattern", json!("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"));
    }
    constrain(&mut contract, "/oneOf/1/definitions/FreelancerProjectV1/properties/currency_code", "pattern", json!("^[A-Z]{3}$"));
    constrain(&mut contract, "/oneOf/2/properties/currency_code", "pattern", json!("^[A-Z]{3}$"));
    constrain(&mut contract, "/oneOf/3/properties/artifact_sha256", "pattern", json!("^[0-9a-f]{64}$"));
    constrain(&mut contract, "/oneOf/3/properties/signer_public_key_ed25519", "pattern", json!("^[0-9a-f]{64}$"));
    constrain(&mut contract, "/oneOf/3/properties/signature_ed25519", "pattern", json!("^[0-9a-f]{128}$"));
    constrain(&mut contract, "/oneOf/1/definitions/FreelancerProjectV1/properties/hourly_rate_minor", "maximum", json!(FREELANCER_MAX_SAFE_MINOR_UNITS_V1));
    constrain(&mut contract, "/oneOf/1/definitions/FreelancerProjectV1/properties/hourly_cost_minor", "maximum", json!(FREELANCER_MAX_SAFE_MINOR_UNITS_V1));
    for path in [
        "/oneOf/2/properties/hourly_rate_minor",
        "/oneOf/2/properties/subtotal_minor",
    ] {
        constrain(&mut contract, path, "maximum", json!(FREELANCER_MAX_SAFE_MINOR_UNITS_V1));
    }
    constrain(&mut contract, "/oneOf/1/definitions/FreelancerProjectV1/properties/label", "maxLength", json!(120));
    constrain(&mut contract, "/oneOf/1/definitions/FreelancerProjectV1/properties/client_alias", "pattern", json!(aliases));
    constrain(&mut contract, "/oneOf/1/definitions/FreelancerCategoryRuleV1/properties/category_path/items", "maxLength", json!(120));
    println!("{}", serde_json::to_string_pretty(&contract).unwrap());
}
