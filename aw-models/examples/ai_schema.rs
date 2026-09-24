use aw_models::{
    AIEndpointProfileV1, AIInsightHistoryV1, AIRequestPreviewV1, AIResultV1, AISettingsV1, AIUserRequestV1,
    SignedAIProviderRegistryV1,
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
        "title": "PeakActivity AI Contract V1",
        "oneOf": [
            schema::<AISettingsV1>(),
            schema::<AIEndpointProfileV1>(),
            schema::<SignedAIProviderRegistryV1>(),
            schema::<AIUserRequestV1>(),
            schema::<AIRequestPreviewV1>(),
            schema::<AIResultV1>(),
            schema::<AIInsightHistoryV1>(),
        ]
    });
    println!("{}", serde_json::to_string_pretty(&contract).unwrap());
}
