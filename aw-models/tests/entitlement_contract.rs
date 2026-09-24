use aw_models::{
    CommercialPackageV1, EntitlementClaimsV1, EntitlementSigningPayloadV1,
    EntitlementRevocationSnapshotV1, PackageCatalogV1, SignedEntitlementV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

fn claims(features: Vec<&str>) -> EntitlementClaimsV1 {
    EntitlementClaimsV1 {
        schema_version: 1,
        entitlement_id: URL_SAFE_NO_PAD.encode([1; 16]),
        account_id: URL_SAFE_NO_PAD.encode([2; 16]),
        plan_id: "plus".into(),
        feature_ids: features.into_iter().map(str::to_owned).collect(),
        issued_at: 1_800_000_000,
        expires_at: 1_831_536_000,
        grace_until: 1_834_128_000,
        device_limit: 3,
    }
}

#[test]
fn signed_entitlement_contract_requires_canonical_features_and_time_bounds() {
    let payload = EntitlementSigningPayloadV1 {
        key_id: "test-key-1".into(),
        claims: claims(vec!["advanced-reports", "e2ee-sync"]),
    };
    let token = SignedEntitlementV1 {
        payload,
        signature: URL_SAFE_NO_PAD.encode([3; 64]),
    };
    assert!(token.validate().is_ok());

    let unsorted = SignedEntitlementV1 {
        payload: EntitlementSigningPayloadV1 {
            key_id: "test-key-1".into(),
            claims: claims(vec!["e2ee-sync", "advanced-reports"]),
        },
        signature: URL_SAFE_NO_PAD.encode([3; 64]),
    };
    assert!(unsorted.validate().is_err());

    let mut invalid_time = claims(vec!["e2ee-sync"]);
    invalid_time.grace_until = invalid_time.expires_at - 1;
    assert!(invalid_time.validate().is_err());
}

#[test]
fn entitlement_contract_rejects_activity_fields_and_duplicate_features() {
    let json = serde_json::json!({
        "payload": {
            "key_id": "test-key-1",
            "claims": {
                "schema_version": 1,
                "entitlement_id": URL_SAFE_NO_PAD.encode([1; 16]),
                "account_id": URL_SAFE_NO_PAD.encode([2; 16]),
                "plan_id": "plus",
                "feature_ids": ["e2ee-sync"],
                "issued_at": 1800000000,
                "expires_at": 1831536000,
                "grace_until": 1834128000,
                "device_limit": 3,
                "window_title": "private marker"
            }
        },
        "signature": URL_SAFE_NO_PAD.encode([3; 64])
    });
    assert!(serde_json::from_value::<SignedEntitlementV1>(json).is_err());
    assert!(claims(vec!["e2ee-sync", "e2ee-sync"]).validate().is_err());
}

#[test]
fn revocation_snapshot_is_monotonic_and_has_no_activity_payload() {
    let snapshot = EntitlementRevocationSnapshotV1 {
        schema_version: 1,
        key_id: "test-key-1".into(),
        sequence: 9,
        issued_at: 1_800_000_000,
        expires_at: 1_800_086_400,
        revoked_entitlement_ids: vec![
            URL_SAFE_NO_PAD.encode([4; 16]),
            URL_SAFE_NO_PAD.encode([5; 16]),
        ],
        signature: URL_SAFE_NO_PAD.encode([6; 64]),
    };
    assert!(snapshot.validate().is_ok());
    assert!(!serde_json::to_string(&snapshot).unwrap().contains("activity"));
    let bytes = snapshot.signing_bytes().unwrap();
    let encoded = String::from_utf8(bytes.clone()).unwrap();
    assert!(!encoded.contains("signature"));
    assert!(encoded.contains("\"sequence\":9"));
    let mut another = snapshot.clone();
    another.sequence += 1;
    assert_ne!(another.signing_bytes().unwrap(), bytes);
}

#[test]
fn entitlement_signing_payload_binds_the_key_id_and_claims() {
    let payload = EntitlementSigningPayloadV1 {
        key_id: "test-key-1".into(),
        claims: claims(vec!["e2ee-sync"]),
    };
    let original = payload.signing_bytes().unwrap();
    let mut changed = payload.clone();
    changed.key_id = "test-key-2".into();
    assert_ne!(changed.signing_bytes().unwrap(), original);
    changed = payload;
    changed.claims.plan_id = "pro".into();
    assert_ne!(changed.signing_bytes().unwrap(), original);
}

#[test]
fn package_catalog_is_unpriced_and_never_gates_always_available_features() {
    let mut catalog = PackageCatalogV1 {
        schema_version: 1,
        prices_published: false,
        always_available_feature_ids: vec!["local-capture".into(), "local-history".into()],
        packages: vec![CommercialPackageV1 {
            id: "community".into(),
            label: "Community".into(),
            status: "Available".into(),
            purchase_model: "free".into(),
            feature_ids: vec![],
            device_limit: None,
            grace_period_seconds: None,
        }, CommercialPackageV1 {
            id: "plus".into(),
            label: "Plus".into(),
            status: "Planned".into(),
            purchase_model: "subscription".into(),
            feature_ids: vec!["e2ee-sync".into()],
            device_limit: None,
            grace_period_seconds: None,
        }],
    };
    assert!(catalog.validate().is_ok());

    catalog.packages[1].status = "Available".into();
    assert!(catalog.validate().is_err());
    catalog.packages[1].device_limit = Some(3);
    catalog.packages[1].grace_period_seconds = Some(604_800);
    assert!(catalog.validate().is_ok());

    catalog.packages[1].feature_ids.push("local-capture".into());
    catalog.packages[1].feature_ids.sort();
    assert!(catalog.validate().is_err());
    let extra_price = serde_json::json!({
        "schema_version": 1,
        "prices_published": false,
        "always_available_feature_ids": [],
        "packages": [],
        "price_cents": 499
    });
    assert!(serde_json::from_value::<PackageCatalogV1>(extra_price).is_err());
}
