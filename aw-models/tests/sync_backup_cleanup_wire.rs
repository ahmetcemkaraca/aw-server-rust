use aw_models::{SyncEnvelopeV1, SyncRelayRequestV1, SyncRelayResponseV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
fn selected() -> Value {
    let envelope = SyncEnvelopeV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([1; 16]),
        vault_id: URL_SAFE_NO_PAD.encode([2; 16]),
        key_epoch: u64::MAX,
        nonce: URL_SAFE_NO_PAD.encode([3; 24]),
        ciphertext: URL_SAFE_NO_PAD.encode([4; 32]),
    };
    json!({"schema_version":1,"operation":"delete_selected_backup","object_id":envelope.object_id,"vault_id":envelope.vault_id,"envelope":envelope})
}
#[test]
fn selected_backup_delete_wire_requires_exact_expected_envelope_and_closed_request() {
    let raw = selected();
    let request: SyncRelayRequestV1 = serde_json::from_value(raw.clone())
        .expect("dedicated backup delete opcode must deserialize");
    request.validate().unwrap();
    assert_eq!(serde_json::to_value(&request).unwrap(), raw);
    for field in ["object_id", "vault_id", "envelope"] {
        let mut missing = raw.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<SyncRelayRequestV1>(missing)
            .unwrap()
            .validate()
            .is_err());
    }
    for (field, value) in [
        ("cursor", json!(URL_SAFE_NO_PAD.encode([5; 16]))),
        ("limit", json!(1)),
        ("object_id", json!(URL_SAFE_NO_PAD.encode([5; 16]))),
        ("vault_id", json!(URL_SAFE_NO_PAD.encode([5; 16]))),
    ] {
        let mut invalid = raw.clone();
        invalid[field] = value;
        assert!(serde_json::from_value::<SyncRelayRequestV1>(invalid)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut unknown = raw.clone();
    unknown["plaintext_title"] = json!("private marker");
    assert!(serde_json::from_value::<SyncRelayRequestV1>(unknown).is_err());
    let mut wrong_version = raw;
    wrong_version["envelope"]["schema_version"] = json!(2);
    assert!(serde_json::from_value::<SyncRelayRequestV1>(wrong_version)
        .unwrap()
        .validate()
        .is_err());
}
#[test]
fn selected_backup_delete_response_is_deleted_boolean_only_including_observed_absence() {
    let request: SyncRelayRequestV1 = serde_json::from_value(selected()).unwrap();
    for deleted in [true, false] {
        let response: SyncRelayResponseV1 =
            serde_json::from_value(json!({"schema_version":1,"deleted":deleted})).unwrap();
        response.validate_for(&request).unwrap();
    }
    for raw in [
        json!({"schema_version":1}),
        json!({"schema_version":1,"deleted":true,"inserted":false}),
        json!({"schema_version":1,"deleted":true,"envelope":selected()["envelope"]}),
        json!({"schema_version":1,"deleted":true,"next_cursor":URL_SAFE_NO_PAD.encode([5;16])}),
        json!({"schema_version":1,"deleted":true,"objects":[selected()["envelope"]]}),
    ] {
        assert!(serde_json::from_value::<SyncRelayResponseV1>(raw)
            .unwrap()
            .validate_for(&request)
            .is_err());
    }
}
