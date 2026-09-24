use aw_models::{EgressApprovalScopeV1, EgressOutcomeV1, EgressReceiptV1};
use aw_server::{
    config::AWConfig,
    endpoints::{self, AssetResolver, ServerState},
    sessions::{Scope, Sessions},
};
use aw_egress::policy_bundle_signing_bytes;
use aw_models::{EgressPolicyBundleV1, EgressPolicyV1, SignedEgressPolicyBundleV1};
use chrono::{DateTime, Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rocket::http::{ContentType, Header, Status};
use serde_json::{json, Value};
use std::collections::HashMap;

fn unsigned_test_bundle() -> Value {
    let vector: Value = serde_json::from_str(include_str!("../../test-vectors/privacy-firewall-v1.json")).unwrap();
    let policy = &vector["policy"];
    json!({
        "schema_version": 1,
        "signer_key_id": "unconfigured-test-key",
        "bundle": {
            "schema_version": 1,
            "version": policy["version"],
            "hard_deny_version": policy["hard_deny_version"],
            "destinations": policy["destinations"],
            "purposes": policy["purposes"],
            "organization_rules": policy["organization_rules"],
        },
        "signature": vec![0_u8; 64],
    })
}

fn signed_test_bundle() -> (SignedEgressPolicyBundleV1, HashMap<String, Vec<u8>>) {
    let vector: Value = serde_json::from_str(include_str!("../../test-vectors/privacy-firewall-v1.json")).unwrap();
    let policy: EgressPolicyV1 = serde_json::from_value(vector["policy"].clone()).unwrap();
    let bundle = EgressPolicyBundleV1 {
        schema_version: 1,
        version: policy.version,
        hard_deny_version: policy.hard_deny_version,
        destinations: policy.destinations,
        purposes: policy.purposes,
        organization_rules: policy.organization_rules,
    };
    let keypair = Ed25519KeyPair::from_seed_unchecked(&[91_u8; 32]).unwrap();
    let mut signed = SignedEgressPolicyBundleV1 {
        schema_version: 1,
        signer_key_id: "route-test-key".into(),
        bundle,
        signature: Vec::new(),
    };
    signed.signature = keypair.sign(&policy_bundle_signing_bytes(&signed).unwrap()).as_ref().to_vec();
    let keys = HashMap::from([("route-test-key".into(), keypair.public_key().as_ref().to_vec())]);
    (signed, keys)
}

#[test]
fn admin_controls_kill_switch_and_reads_content_free_receipts() {
    let sessions = Sessions::new(5600, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let read = sessions.mint(Scope::Read).unwrap();
    let query = sessions.mint(Scope::Query).unwrap();
    let ingest = sessions.mint(Scope::Ingest(vec!["aw-watcher-window_".into()])).unwrap();
    let datastore = aw_datastore::Datastore::new_in_memory(false);
    datastore.record_egress_receipt(&EgressReceiptV1 {
        schema_version: 1,
        destination_id: "sync-relay".into(),
        purpose_id: "sync".into(),
        retention_id: "test-session".into(),
        allowed_fields: vec!["/timestamp".into(), "/app".into()],
        policy_version: 3,
        scope: EgressApprovalScopeV1::Once,
        decision: EgressOutcomeV1::Allow,
        created_at: DateTime::parse_from_rfc3339("2026-09-23T12:00:00Z").unwrap().with_timezone(&Utc),
    }).unwrap();
    let state = ServerState { datastore: datastore.clone(), asset_resolver: AssetResolver::new(None), device_id: "synthetic".into() };
    let mut config = AWConfig::default();
    config.port = 5600;
    config.auth.sessions = Some(sessions);
    let client = rocket::local::blocking::Client::tracked(endpoints::build_rocket(state, config)).unwrap();
    let auth = |token: &str| Header::new("Authorization", format!("Bearer {token}"));
    let host = Header::new("Host", "localhost:5600");

    assert_eq!(client.get("/api/0/egress/status").header(host.clone()).dispatch().status(), Status::Unauthorized);
    for token in [&read, &query, &ingest] {
        assert_eq!(client.get("/api/0/egress/status").header(host.clone()).header(auth(token)).dispatch().status(), Status::Forbidden);
        assert_eq!(client.get("/api/0/egress/user-policy").header(host.clone()).header(auth(token)).dispatch().status(), Status::Forbidden);
        assert_eq!(client.get("/api/0/egress/approvals").header(host.clone()).header(auth(token)).dispatch().status(), Status::Forbidden);
        assert_eq!(client.get("/api/0/egress/policy").header(host.clone()).header(auth(token)).dispatch().status(), Status::Forbidden);
        let denied = client.post("/api/0/egress/policy/diff")
            .header(host.clone()).header(auth(token)).header(ContentType::JSON).body("{}").dispatch();
        assert_eq!(denied.status(), Status::Forbidden);
        let denied = client.put("/api/0/egress/policy/accept")
            .header(host.clone()).header(auth(token)).header(ContentType::JSON).body("{}").dispatch();
        assert_eq!(denied.status(), Status::Forbidden);
        let denied = client.post("/api/0/egress/user-policy/diff")
            .header(host.clone()).header(auth(token)).header(ContentType::JSON)
            .body(r#"{"schema_version":1,"user_rules":[],"safe_zone_patterns":[],"after_hours":null}"#).dispatch();
        assert_eq!(denied.status(), Status::Forbidden);
        let denied = client.put("/api/0/egress/user-policy/accept")
            .header(host.clone()).header(auth(token)).header(ContentType::JSON)
            .body(r#"{"preview_id":"test"}"#).dispatch();
        assert_eq!(denied.status(), Status::Forbidden);
        let denied = client.post("/api/0/egress/kill-switch")
            .header(host.clone()).header(auth(token)).header(ContentType::JSON)
            .body(r#"{"enabled":false}"#).dispatch();
        assert_eq!(denied.status(), Status::Forbidden);
        assert_eq!(client.delete("/api/0/egress/approvals").header(host.clone()).header(auth(token)).dispatch().status(), Status::Forbidden);
        let denied = client.post("/api/0/egress/approve")
            .header(host.clone()).header(auth(token)).header(ContentType::JSON)
            .body(r#"{"preview_id":"test","scope":"once","expires_at":null}"#).dispatch();
        assert_eq!(denied.status(), Status::Forbidden);
    }
    let status = client.get("/api/0/egress/status").header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(status.status(), Status::Ok);
    let status: Value = serde_json::from_str(&status.into_string().unwrap()).unwrap();
    assert_eq!(status["kill_switch_enabled"], true);
    assert_eq!(status["trusted_policy_keys"], 0);
    assert_eq!(status["outbound_enabled"], false);

    assert_eq!(client.get("/api/0/egress/policy").header(host.clone()).header(auth(&admin)).dispatch().status(), Status::ServiceUnavailable);
    let candidate = unsigned_test_bundle();
    let diff = client.post("/api/0/egress/policy/diff")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(serde_json::to_string(&candidate).unwrap()).dispatch();
    assert_eq!(diff.status(), Status::ServiceUnavailable);
    let accept = client.put("/api/0/egress/policy/accept")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "accept": true,
            "bundle": candidate,
            "expected_diff": {
                "schema_version": 1, "from_version": 0, "to_version": 3,
                "hard_deny_version_before": 0, "hard_deny_version_after": 1,
                "added_destinations": [], "removed_destinations": [], "changed_destinations": [],
                "added_purposes": [], "removed_purposes": [], "changed_purposes": [],
                "added_organization_rules": [], "removed_organization_rules": [],
                "added_user_rules": [], "removed_user_rules": [],
                "added_safe_zone_patterns": [], "removed_safe_zone_patterns": [],
                "after_hours_before": null, "after_hours_after": null
            }
        })).unwrap()).dispatch();
    assert_eq!(accept.status(), Status::ServiceUnavailable);

    let revoke = client.delete("/api/0/egress/approvals").header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(revoke.status(), Status::Ok);

    let user_policy = r#"{"schema_version":1,"user_rules":[{"pattern":{"kind":"keyword","value":"banking"},"action":"deny"}],"safe_zone_patterns":[{"kind":"application","value":"personal"}],"after_hours":{"weekdays":[1,2,3,4,5],"start_minute":1080,"end_minute":480}}"#;
    let user_diff = client.post("/api/0/egress/user-policy/diff")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(user_policy).dispatch();
    assert_eq!(user_diff.status(), Status::Ok);
    let user_diff: Value = serde_json::from_str(&user_diff.into_string().unwrap()).unwrap();
    assert_eq!(user_diff["diff"]["added_user_rules"].as_array().unwrap().len(), 1);
    let saved_policy = client.put("/api/0/egress/user-policy/accept")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(serde_json::to_string(&json!({ "preview_id": user_diff["preview_id"] })).unwrap()).dispatch();
    assert_eq!(saved_policy.status(), Status::Ok);
    let policy = client.get("/api/0/egress/user-policy").header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(policy.status(), Status::Ok);
    assert_eq!(serde_json::from_str::<Value>(&policy.into_string().unwrap()).unwrap(), serde_json::from_str::<Value>(user_policy).unwrap());
    let invalid_policy = client.post("/api/0/egress/user-policy/diff")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"schema_version":1,"user_rules":[],"safe_zone_patterns":[],"after_hours":{"weekdays":[1],"start_minute":600,"end_minute":600}}"#).dispatch();
    assert_eq!(invalid_policy.status(), Status::BadRequest);

    let preview = client.post("/api/0/egress/preview")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"schema_version":1,"destination_id":"sync-relay","purpose_id":"sync","retention_id":"test-session","payload":{"app":"synthetic-private-app"}}"#)
        .dispatch();
    assert_eq!(preview.status(), Status::ServiceUnavailable);
    assert!(!preview.into_string().unwrap().contains("synthetic-private-app"));

    let send = client.post("/api/0/egress/send")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"preview_id":"synthetic","approval_id":"synthetic"}"#)
        .dispatch();
    assert_eq!(send.status(), Status::ServiceUnavailable);

    let receipts = client.get("/api/0/egress/receipts?limit=10").header(host.clone()).header(auth(&admin)).dispatch();
    assert_eq!(receipts.status(), Status::Ok);
    let receipts: Value = serde_json::from_str(&receipts.into_string().unwrap()).unwrap();
    assert_eq!(receipts.as_array().unwrap().len(), 1);
    assert!(receipts[0].get("payload").is_none());
    assert!(receipts[0].get("sanitized_payload").is_none());

    let toggle = client.post("/api/0/egress/kill-switch")
        .header(host.clone()).header(auth(&admin)).header(ContentType::JSON)
        .body(r#"{"enabled":false}"#).dispatch();
    assert_eq!(toggle.status(), Status::Ok);
    let status = client.get("/api/0/egress/status").header(host.clone()).header(auth(&admin)).dispatch();
    let status: Value = serde_json::from_str(&status.into_string().unwrap()).unwrap();
    assert_eq!(status["kill_switch_enabled"], false);

    let now = Utc::now();
    let payload_tag = [7_u8; 32];
    let approval_id = datastore.create_egress_approval(
        "sync-relay", "sync", "test-session", 3, EgressApprovalScopeV1::Once,
        payload_tag, Some(now + Duration::seconds(10)), now,
    ).unwrap();
    let revoke = client.delete("/api/0/egress/approvals").header(host).header(auth(&admin)).dispatch();
    assert_eq!(revoke.status(), Status::Ok);
    assert!(datastore.consume_egress_approval(
        &approval_id, "sync-relay", "sync", "test-session", 3, payload_tag, now,
    ).is_err());
}

#[test]
fn signed_policy_requires_exact_diff_acceptance_and_rejects_replay() {
    let sessions = Sessions::new(5601, false);
    let admin = sessions.mint(Scope::Admin).unwrap();
    let datastore = aw_datastore::Datastore::new_in_memory(false);
    let state = ServerState { datastore: datastore.clone(), asset_resolver: AssetResolver::new(None), device_id: "synthetic".into() };
    let mut config = AWConfig::default();
    config.port = 5601;
    config.auth.sessions = Some(sessions);
    let (bundle, keys) = signed_test_bundle();
    let trust = endpoints::EgressPolicyTrust::from_release_keys(keys);
    let client = rocket::local::blocking::Client::tracked(
        endpoints::build_rocket_with_policy_trust(state, config, trust),
    ).unwrap();
    let auth = Header::new("Authorization", format!("Bearer {admin}"));
    let host = Header::new("Host", "localhost:5601");

    let diff = client.post("/api/0/egress/policy/diff")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::to_string(&bundle).unwrap()).dispatch();
    assert_eq!(diff.status(), Status::Ok);
    let expected_diff: Value = serde_json::from_str(&diff.into_string().unwrap()).unwrap();
    assert_eq!(expected_diff["from_version"], 0);
    assert_eq!(expected_diff["to_version"], bundle.bundle.version);
    assert_eq!(expected_diff["added_destinations"].as_array().unwrap().len(), 1);

    let mut altered_diff = expected_diff.clone();
    altered_diff["to_version"] = json!(99);
    let rejected = client.put("/api/0/egress/policy/accept")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::to_string(&json!({ "accept": true, "bundle": bundle, "expected_diff": altered_diff })).unwrap()).dispatch();
    assert_eq!(rejected.status(), Status::Conflict);
    assert!(datastore.get_egress_policy_state().unwrap().is_none());

    let acceptance = json!({ "accept": true, "bundle": bundle, "expected_diff": expected_diff });
    let accepted = client.put("/api/0/egress/policy/accept")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::to_string(&acceptance).unwrap()).dispatch();
    assert_eq!(accepted.status(), Status::Ok);
    assert_eq!(datastore.get_egress_policy_state().unwrap().unwrap().0.bundle.version, 3);
    assert_eq!(client.get("/api/0/egress/policy").header(host.clone()).header(auth.clone()).dispatch().status(), Status::Ok);

    datastore.set_egress_kill_switch(false).unwrap();
    let preview = client.post("/api/0/egress/preview")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(r#"{"schema_version":1,"destination_id":"sync-relay","purpose_id":"sync","retention_id":"test-session","payload":{"timestamp":"2026-09-23T12:00:00Z","app":"Editor"}}"#)
        .dispatch();
    assert_eq!(preview.status(), Status::Ok);
    let preview: Value = serde_json::from_str(&preview.into_string().unwrap()).unwrap();
    assert_eq!(preview["destination_id"], "sync-relay");
    assert_eq!(preview["destination_origin"], "https://relay.example.test");
    assert_eq!(preview["purpose_id"], "sync");
    assert_eq!(preview["retention_id"], "test-session");
    assert_eq!(preview["retention_disclosure"], "Synthetic test destination; no request is sent.");
    assert_eq!(preview["decision"]["outcome"], "allow");

    let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let approval = client.post("/api/0/egress/approve")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "preview_id": preview["decision"]["preview_id"],
            "scope": "time_limited",
            "expires_at": expires_at,
        })).unwrap()).dispatch();
    assert_eq!(approval.status(), Status::Ok);
    let approval: Value = serde_json::from_str(&approval.into_string().unwrap()).unwrap();
    assert_eq!(approval["scope"], "time_limited");
    assert!(approval.get("payload_tag").is_none());
    let approvals = client.get("/api/0/egress/approvals").header(host.clone()).header(auth.clone()).dispatch();
    assert_eq!(approvals.status(), Status::Ok);
    let approvals: Value = serde_json::from_str(&approvals.into_string().unwrap()).unwrap();
    assert_eq!(approvals.as_array().unwrap().len(), 1);

    let send = client.post("/api/0/egress/send")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "preview_id": preview["decision"]["preview_id"],
            "approval_id": approval["approval_id"],
        })).unwrap()).dispatch();
    assert_eq!(send.status(), Status::Forbidden); // .test destination is rejected before a network request.

    let same_payload_preview = client.post("/api/0/egress/preview")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(r#"{"schema_version":1,"destination_id":"sync-relay","purpose_id":"sync","retention_id":"test-session","payload":{"timestamp":"2026-09-23T12:00:00Z","app":"Editor"}}"#).dispatch();
    let same_payload_preview: Value = serde_json::from_str(&same_payload_preview.into_string().unwrap()).unwrap();
    let repeated_send = client.post("/api/0/egress/send")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "preview_id": same_payload_preview["decision"]["preview_id"],
            "approval_id": approval["approval_id"],
        })).unwrap()).dispatch();
    assert_eq!(repeated_send.status(), Status::Forbidden);

    let changed_payload_preview = client.post("/api/0/egress/preview")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(r#"{"schema_version":1,"destination_id":"sync-relay","purpose_id":"sync","retention_id":"test-session","payload":{"timestamp":"2026-09-23T12:00:00Z","app":"Different Editor"}}"#).dispatch();
    let changed_payload_preview: Value = serde_json::from_str(&changed_payload_preview.into_string().unwrap()).unwrap();
    let changed_send = client.post("/api/0/egress/send")
        .header(host.clone()).header(auth.clone()).header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "preview_id": changed_payload_preview["decision"]["preview_id"],
            "approval_id": approval["approval_id"],
        })).unwrap()).dispatch();
    assert_eq!(changed_send.status(), Status::Conflict);

    let approvals = client.get("/api/0/egress/approvals").header(host.clone()).header(auth.clone()).dispatch();
    let approvals: Value = serde_json::from_str(&approvals.into_string().unwrap()).unwrap();
    assert_eq!(approvals.as_array().unwrap().len(), 1);
    assert_eq!(client.delete("/api/0/egress/approvals").header(host.clone()).header(auth.clone()).dispatch().status(), Status::Ok);

    let replay = client.put("/api/0/egress/policy/accept")
        .header(host).header(auth).header(ContentType::JSON)
        .body(serde_json::to_string(&acceptance).unwrap()).dispatch();
    assert_eq!(replay.status(), Status::Conflict);
}
