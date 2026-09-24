use aw_models::{
    CommercialPackageV1, EntitlementClaimsV1, EntitlementRevocationSnapshotV1,
    EntitlementSigningPayloadV1, PackageCatalogV1, SignedEntitlementV1,
};
use schemars::{schema_for, JsonSchema};
use serde_json::{json, Value};

fn schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T)).unwrap()
}

fn main() {
    let mut contract = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "PeakActivity Commercial Entitlement Contract V1",
        "oneOf": [
            schema::<EntitlementClaimsV1>(),
            schema::<EntitlementSigningPayloadV1>(),
            schema::<SignedEntitlementV1>(),
            schema::<EntitlementRevocationSnapshotV1>(),
            schema::<CommercialPackageV1>(),
            schema::<PackageCatalogV1>(),
        ]
    });
    for schema in contract["oneOf"].as_array_mut().unwrap() {
        if let Some(version) = schema.pointer_mut("/properties/schema_version") {
            *version = json!({"const": 1, "type": "integer"});
        }
    }
    println!("{}", serde_json::to_string_pretty(&contract).unwrap());
}
