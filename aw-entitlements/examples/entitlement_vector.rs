use aw_models::{
    EntitlementClaimsV1, EntitlementSigningPayloadV1, SignedEntitlementV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;

fn main() {
    let keypair = Ed25519KeyPair::from_seed_unchecked(&[0xA5; 32]).unwrap();
    let payload = EntitlementSigningPayloadV1 {
        key_id: "test-entitlement-key-v1".into(),
        claims: EntitlementClaimsV1 {
            schema_version: 1,
            entitlement_id: URL_SAFE_NO_PAD.encode([0x31; 16]),
            account_id: URL_SAFE_NO_PAD.encode([0x32; 16]),
            plan_id: "plus".into(),
            feature_ids: vec!["e2ee-sync".into()],
            issued_at: 1_899_999_940,
            expires_at: 1_900_000_100,
            grace_until: 1_900_003_600,
            device_limit: 3,
        },
    };
    let token = SignedEntitlementV1 {
        signature: URL_SAFE_NO_PAD.encode(keypair.sign(&payload.signing_bytes().unwrap()).as_ref()),
        payload,
    };
    println!("{}", serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "now": 1_900_000_000,
        "public_key": URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()),
        "signing_bytes": String::from_utf8(token.payload.signing_bytes().unwrap()).unwrap(),
        "entitlement": token,
    })).unwrap());
}
