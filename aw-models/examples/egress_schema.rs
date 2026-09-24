use aw_models::{
    EgressApprovalV1, EgressDecisionV1, EgressPolicyBundleV1, EgressPolicyDiffV1, EgressPolicyV1,
    EgressPreviewV1, EgressReceiptV1, EgressRequestV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
};
use schemars::{schema_for, JsonSchema};
use serde_json::{json, Value};

fn schema<T: JsonSchema>() -> Value {
    let mut value = serde_json::to_value(schema_for!(T)).unwrap();
    if let Some(version) = value.pointer_mut("/properties/schema_version") {
        *version = json!({"const": 1, "type": "integer"});
    }
    value
}

fn main() {
    let contract = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "PeakActivity Egress Contract V1",
        "oneOf": [
            schema::<EgressRequestV1>(),
            schema::<EgressApprovalV1>(),
            schema::<EgressDecisionV1>(),
            schema::<EgressPreviewV1>(),
            schema::<EgressPolicyBundleV1>(),
            schema::<EgressPolicyDiffV1>(),
            schema::<EgressPolicyV1>(),
            schema::<EgressReceiptV1>(),
            schema::<EgressUserPolicyV1>(),
            schema::<SignedEgressPolicyBundleV1>(),
        ]
    });
    println!("{}", serde_json::to_string_pretty(&contract).unwrap());
}
