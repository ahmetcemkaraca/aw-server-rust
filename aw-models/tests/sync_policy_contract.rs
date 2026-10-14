use aw_models::{
    SyncPolicyChoiceRequestV1, SyncPolicyContractErrorV1, SyncPolicyValueV1,
    SYNC_POLICY_MAX_FIELD_BYTES_V1,
};
use serde_json::json;

fn choice() -> serde_json::Value {
    json!({"schema_version":1,"candidate_id":"a".repeat(64),"expected_review_sha256":"b".repeat(64),"decision":"keep-local"})
}

#[test]
fn recovery_policy_wire_records_are_closed_map_only_and_collections_are_bounded() {
    use aw_models::SyncRecoveryPolicyV1;
    let value = json!({"schema_version":1,"active_values":[],"decisions":[]});
    serde_json::from_value::<SyncRecoveryPolicyV1>(value.clone()).unwrap();
    for bad in [json!([1,[],[]]),json!({"schema_version":1,"active_values":[],"decisions":[],"trusted":true})] {
        assert!(serde_json::from_value::<SyncRecoveryPolicyV1>(bad).is_err());
    }
    let field = json!({"field":"settings.theme","value":{"schema_version":1,"present":true,"value":"dark"}});
    let decision = json!({"field":"settings.theme","candidate_ids":["a".repeat(64)],"active_binding_sha256":"b".repeat(64)});
    for (key, entry) in [("active_values",field),("decisions",decision)] {
        let mut too_many = value.clone();too_many[key] = json!(vec![entry;22]);
        assert!(serde_json::from_value::<SyncRecoveryPolicyV1>(too_many).is_err());
    }
    for invalid in [
        json!({"schema_version":1,"active_values":[["settings.theme",{"schema_version":1,"present":true,"value":"dark"}]],"decisions":[]}),
        json!({"schema_version":1,"active_values":[],"decisions":[{"field":"x".repeat(65),"candidate_ids":[],"active_binding_sha256":"b".repeat(64)}]}),
        json!({"schema_version":1,"active_values":[],"decisions":[{"field":"settings.theme","candidate_ids":["a".repeat(65)],"active_binding_sha256":"b".repeat(64)}]}),
    ] {assert!(serde_json::from_value::<SyncRecoveryPolicyV1>(invalid).is_err());}
    assert!(serde_json::from_str::<SyncRecoveryPolicyV1>("{\"schema_version\":1,\"schema_version\":1,\"active_values\":[],\"decisions\":[]}").is_err());
    let source=json!({"schema_version":1,"vault_id":"AgICAgICAgICAgICAgICAg","key_epoch":"1","snapshot_id":"AwMDAwMDAwMDAwMDAwMDAw"});
    let entry=json!({"schema_version":1,"source":source,"field":"settings.theme","value":{"schema_version":1,"present":true,"value":"dark"}});
    let mut policy=value.clone();policy["pending_recovery"]=json!([entry.clone()]);
    assert_eq!(serde_json::from_value::<SyncRecoveryPolicyV1>(policy.clone()).unwrap().pending_recovery.len(),1);
    for bad in [json!([1,source,"settings.theme",entry["value"]]),json!({"schema_version":1,"source":source,"field":"settings.theme","value":entry["value"],"trusted":true})] {
        policy["pending_recovery"]=json!([bad]);assert!(serde_json::from_value::<SyncRecoveryPolicyV1>(policy.clone()).is_err());
    }
}

#[test]
fn sync_policy_choice_requires_an_explicit_bound_known_decision() {
    for decision in ["keep-local", "accept-remote"] {
        let mut value = choice();
        value["decision"] = json!(decision);
        serde_json::from_value::<SyncPolicyChoiceRequestV1>(value)
            .unwrap()
            .validate()
            .unwrap();
    }
    for (field, value) in [
        ("schema_version", json!(2)),
        ("candidate_id", json!("A".repeat(64))),
        ("expected_review_sha256", json!("b".repeat(63))),
    ] {
        let mut request = choice();
        request[field] = value;
        assert_eq!(
            serde_json::from_value::<SyncPolicyChoiceRequestV1>(request)
                .unwrap()
                .validate(),
            Err(SyncPolicyContractErrorV1::Invalid)
        );
    }
    let mut invalid = choice();
    invalid["decision"] = json!("enable-sync");
    assert!(serde_json::from_value::<SyncPolicyChoiceRequestV1>(invalid).is_err());
}

#[test]
fn sync_policy_choice_rejects_arrays_unknown_and_duplicate_fields() {
    for raw in [
        format!(
            "[1,\"{}\",\"{}\",\"keep-local\"]",
            "a".repeat(64),
            "b".repeat(64)
        ),
        choice().to_string().replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        choice().to_string().replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"trusted\":true",
        ),
    ] {
        assert!(serde_json::from_str::<SyncPolicyChoiceRequestV1>(&raw).is_err());
    }
}

#[test]
fn sync_policy_choice_rejects_oversize_identifiers_during_decoding() {
    for field in ["candidate_id", "expected_review_sha256"] {
        for value in ["a".repeat(65), "🧑".repeat(17)] {
            let mut request = choice();request[field] = json!(value);
            assert!(serde_json::from_value::<SyncPolicyChoiceRequestV1>(request).is_err());
        }
    }
}

#[test]
fn sync_policy_values_distinguish_absence_stored_null_and_empty() {
    let absent: SyncPolicyValueV1 =
        serde_json::from_value(json!({"schema_version":1,"present":false,"value":null})).unwrap();
    let null: SyncPolicyValueV1 =
        serde_json::from_value(json!({"schema_version":1,"present":true,"value":null})).unwrap();
    let empty: SyncPolicyValueV1 =
        serde_json::from_value(json!({"schema_version":1,"present":true,"value":[]})).unwrap();
    for value in [&absent, &null, &empty] {
        value.validate().unwrap();
    }
    assert_ne!(absent, null);
    assert_ne!(null, empty);
    let invalid: SyncPolicyValueV1 =
        serde_json::from_value(json!({"schema_version":1,"present":false,"value":[]})).unwrap();
    assert_eq!(invalid.validate(), Err(SyncPolicyContractErrorV1::Invalid));
}

#[test]
fn sync_policy_value_rejects_arrays_unknown_duplicate_and_nonfinite_json() {
    for raw in [
        "[1,true,null]",
        "{\"schema_version\":1,\"present\":true,\"value\":null,\"unchecked\":1}",
        "{\"schema_version\":1,\"present\":true,\"present\":false,\"value\":null}",
        "{\"schema_version\":1,\"present\":true,\"value\":1e400}",
    ] {
        assert!(serde_json::from_str::<SyncPolicyValueV1>(raw).is_err());
    }
}

#[test]
fn sync_policy_value_admits_the_exact_encoded_byte_boundary_and_rejects_growth() {
    let mut value: SyncPolicyValueV1 =
        serde_json::from_value(json!({"schema_version":1,"present":true,"value":""})).unwrap();
    let overhead = serde_json::to_vec(&value).unwrap().len();
    value.value = json!("x".repeat(SYNC_POLICY_MAX_FIELD_BYTES_V1 - overhead));
    assert_eq!(
        serde_json::to_vec(&value).unwrap().len(),
        SYNC_POLICY_MAX_FIELD_BYTES_V1
    );
    value.validate().unwrap();
    value.value = json!("x".repeat(SYNC_POLICY_MAX_FIELD_BYTES_V1 - overhead + 1));
    assert_eq!(value.validate(), Err(SyncPolicyContractErrorV1::ByteLimit));
    value.value = json!("Ł".repeat(SYNC_POLICY_MAX_FIELD_BYTES_V1 / 2));
    assert_eq!(value.validate(), Err(SyncPolicyContractErrorV1::ByteLimit));
}
