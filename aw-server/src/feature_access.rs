//! Signed billing proof is supplied by a native source, never stored in activity data.
use aw_entitlements::{
    RuntimeFeatureAccessErrorV1, RuntimeFeatureAccessV1, StoredEntitlementV1, VerifiedEntitlementV1,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn current_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| "The system clock is unavailable".into())
}

pub fn error_message(error: RuntimeFeatureAccessErrorV1) -> String {
    match error {
        RuntimeFeatureAccessErrorV1::Source(_) => {
            "The separate entitlement store is unavailable".into()
        }
        RuntimeFeatureAccessErrorV1::MissingEntitlement => {
            "Import a current signed plan to enable paid sync".into()
        }
        RuntimeFeatureAccessErrorV1::MissingFeature => {
            "This signed plan does not include encrypted sync".into()
        }
        RuntimeFeatureAccessErrorV1::Verification(_) => {
            "The signed plan is invalid, expired or revoked".into()
        }
    }
}

pub fn public_status(
    access: &RuntimeFeatureAccessV1,
    verified: VerifiedEntitlementV1,
    now: u64,
) -> Value {
    json!({"plan_id":verified.claims.plan_id,"feature_ids":verified.claims.feature_ids,
        "expires_at":verified.claims.expires_at,"grace_until":verified.claims.grace_until,"access":verified.access,
        "sync_allowed":access.require_sync_access(now).is_ok()})
}

pub fn invoke(
    access: &Arc<RuntimeFeatureAccessV1>,
    command: &str,
    arguments: Value,
) -> Option<Result<Value, String>> {
    Some(match command {
        "entitlement_status" => (|| {
            if arguments.as_object().is_none_or(|args| !args.is_empty()) {
                return Err("The entitlement status request is invalid".into());
            }
            let now = current_time()?;
            access.status(now).map_err(error_message).map(|verified| {
                verified
                    .map(|verified| public_status(access, verified, now))
                    .unwrap_or(Value::Null)
            })
        })(),
        "import_entitlement" => (|| {
            let object = arguments
                .as_object()
                .ok_or("The signed plan import is invalid")?;
            if object.len() != 1 {
                return Err("The signed plan import is invalid".into());
            }
            let proof = object
                .get("proof")
                .filter(|value| value.is_object())
                .ok_or("Choose a signed plan document")?;
            let proof: StoredEntitlementV1 = serde_json::from_value(proof.clone())
                .map_err(|_| "The signed plan document is invalid")?;
            let now = current_time()?;
            access
                .install(proof, now)
                .map(|verified| public_status(access, verified, now))
                .map_err(error_message)
        })(),
        _ => return None,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEntitlementTrust {
    schema_version: u16,
    keys: Vec<ReleaseEntitlementKey>,
    minimum_revocation_sequence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseEntitlementKey {
    id: String,
    ed25519_public_key: [u8; 32],
}

pub fn parse_release_entitlement_trust(
    bytes: &[u8],
) -> Result<(BTreeMap<String, [u8; 32]>, u64), &'static str> {
    const INVALID: &str = "The embedded entitlement trust resource is invalid";
    if bytes.is_empty() {
        return Ok((BTreeMap::new(), 0));
    }
    if bytes.len() > 16_384
        || !bytes
            .iter()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| *byte == b'{')
    {
        return Err(INVALID);
    }
    let trust: ReleaseEntitlementTrust = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    let shape: Value = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    if trust.schema_version != 1
        || trust.keys.len() > 32
        || shape["keys"]
            .as_array()
            .is_none_or(|keys| keys.iter().any(|key| !key.is_object()))
    {
        return Err(INVALID);
    }
    let mut keys = BTreeMap::new();
    for key in trust.keys {
        if key.id.is_empty()
            || key.id.len() > 64
            || !key
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || keys.insert(key.id, key.ed25519_public_key).is_some()
        {
            return Err(INVALID);
        }
    }
    Ok((keys, trust.minimum_revocation_sequence))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entitlement_release_trust_is_separate_strict_and_empty_by_default() {
        assert_eq!(
            parse_release_entitlement_trust(&[]).unwrap(),
            (BTreeMap::new(), 0)
        );
        assert!(parse_release_entitlement_trust(
            br#"{"schema_version":1,"keys":[],"minimum_revocation_sequence":0}"#
        )
        .unwrap()
        .0
        .is_empty());
        for value in [
            json!({"schema_version":2,"keys":[],"minimum_revocation_sequence":0}),
            json!({"schema_version":1,"keys":[],"minimum_revocation_sequence":0,"root":true}),
            json!([1, [], 0]),
            json!({"schema_version":1,"keys":[["key",vec![1;32]]],"minimum_revocation_sequence":0}),
        ] {
            assert!(parse_release_entitlement_trust(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(parse_release_entitlement_trust(
            br#"{"schema_version":1,"schema_version":1,"keys":[],"minimum_revocation_sequence":0}"#
        )
        .is_err());
        let key = json!({"id":"entitlement-release","ed25519_public_key":vec![1;32]});
        assert!(parse_release_entitlement_trust(&serde_json::to_vec(&json!({"schema_version":1,"keys":[key.clone(),key],"minimum_revocation_sequence":0})).unwrap()).is_err());
        for id in ["release_key", "release.key"] {
            assert!(parse_release_entitlement_trust(
                &serde_json::to_vec(&json!({"schema_version":1,"keys":[
                {"id":id,"ed25519_public_key":vec![1;32]}],"minimum_revocation_sequence":0}))
                .unwrap()
            )
            .is_err());
        }
    }
}
