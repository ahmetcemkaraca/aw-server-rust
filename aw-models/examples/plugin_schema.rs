use aw_models::{
    PluginCapabilityDiffV1, PluginManifestV1, PluginCapabilitiesV1,
    PluginInvocationInputV1, PluginInvocationOutputV1, SignedPluginPackageV1,
};
use schemars::{schema_for, JsonSchema};
use serde_json::{json, Value};

fn schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T)).unwrap()
}

fn main() {
    let contract = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "PeakActivity Plugin Contract V1",
        "oneOf": [
            schema::<PluginManifestV1>(),
            schema::<SignedPluginPackageV1>(),
            schema::<PluginCapabilityDiffV1>(),
            schema::<PluginCapabilitiesV1>(),
            schema::<PluginInvocationInputV1>(),
            schema::<PluginInvocationOutputV1>(),
        ]
    });
    println!("{}", serde_json::to_string_pretty(&contract).unwrap());
}
