use aw_models::{
    DevicePublicIdentityV1, EncryptedKeyTransferV1, PairingConfirmationV1, PairingInvitationV1,
    PairingOfferV1, PairingResponseV1, RecoveryKitV1, SyncBucketDescriptorV1, SyncChunkHeaderV1, SyncEnvelopeV1,
    SyncOperationKindV1, SyncRelayOperationV1, SyncRelayRequestV1, SyncRelayResponseV1,
};
use schemars::{schema_for, JsonSchema};
use serde_json::{json, Value};

fn schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T)).unwrap()
}

fn main() {
    let mut contract = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "PeakActivity E2EE Sync Contract V1",
        "oneOf": [
            schema::<SyncChunkHeaderV1>(),
            schema::<SyncEnvelopeV1>(),
            schema::<DevicePublicIdentityV1>(),
            schema::<SyncBucketDescriptorV1>(),
            schema::<PairingInvitationV1>(),
            schema::<PairingResponseV1>(),
            schema::<PairingOfferV1>(),
            schema::<PairingConfirmationV1>(),
            schema::<EncryptedKeyTransferV1>(),
            schema::<RecoveryKitV1>(),
            schema::<SyncOperationKindV1>(),
            schema::<SyncRelayOperationV1>(),
            schema::<SyncRelayRequestV1>(),
            schema::<SyncRelayResponseV1>(),
        ]
    });
    for schema in contract["oneOf"].as_array_mut().unwrap() {
        if let Some(version) = schema.pointer_mut("/properties/schema_version") {
            *version = json!({"const": 1, "type": "integer"});
        }
    }
    println!("{}", serde_json::to_string_pretty(&contract).unwrap());
}
