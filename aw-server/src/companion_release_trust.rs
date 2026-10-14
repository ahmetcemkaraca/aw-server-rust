//! Release-owned app bundle public keys, never accepted by a normal native command.
use std::collections::HashMap;
use serde::Deserialize;

pub const MAX_RELEASE_TRUST_BYTES: usize = 16_384;
pub const MAX_RELEASE_TRUST_KEYS: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrustResource {
    schema_version: u16,
    keys: Vec<ReleaseTrustKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrustKey {
    id: String,
    ed25519_public_key: [u8; 32],
}

pub fn parse_release_trust(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>, &'static str> {
    const INVALID: &str = "The embedded release trust resource is invalid";
    if bytes.is_empty() { return Ok(HashMap::new()); }
    if bytes.len() > MAX_RELEASE_TRUST_BYTES { return Err(INVALID); }
    let resource: ReleaseTrustResource = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    // Derived struct deserialization accepts sequences too. Check object shapes
    // separately; the typed parse above retains duplicate-field rejection.
    let shape: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    if !shape.is_object()
        || shape["keys"].as_array().ok_or(INVALID)?.iter().any(|key| !key.is_object())
        || resource.schema_version != 1
        || resource.keys.len() > MAX_RELEASE_TRUST_KEYS
    {
        return Err(INVALID);
    }
    let mut keys = HashMap::with_capacity(resource.keys.len());
    for key in resource.keys {
        // Match the aw-egress release signer ID grammar.
        if key.id.is_empty() || key.id.len() > 64
            || !key.id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')))
            })
            || keys.insert(key.id, key.ed25519_public_key.to_vec()).is_some()
        {
            return Err(INVALID);
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn resource(keys: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema_version":1,"keys":keys})).unwrap()
    }

    fn key(id: &str) -> serde_json::Value {
        json!({"id":id,"ed25519_public_key":vec![0x41;32]})
    }

    #[test]
    fn absent_and_explicit_empty_resources_do_not_establish_trust() {
        assert!(parse_release_trust(&[]).unwrap().is_empty());
        assert!(parse_release_trust(&resource(json!([]))).unwrap().is_empty());
    }

    #[test]
    fn configured_resource_retains_exact_ids_and_key_bytes() {
        let bytes = resource(json!([key("release-key.v1"),key("another_2")]));
        let parsed = parse_release_trust(&bytes).unwrap();
        assert_eq!(parsed.len(),2);
        assert_eq!(parsed["release-key.v1"],vec![0x41;32]);
        assert_eq!(parsed["another_2"],vec![0x41;32]);
    }

    #[test]
    fn duplicate_ids_and_object_fields_are_rejected() {
        assert!(parse_release_trust(&resource(json!([key("duplicate"),key("duplicate")]))).is_err());
        assert!(parse_release_trust(br#"{"schema_version":1,"schema_version":1,"keys":[]}"#).is_err());
        assert!(parse_release_trust(br#"{"schema_version":1,"keys":[],"keys":[]}"#).is_err());
        let repeated = format!("{{\"schema_version\":1,\"keys\":[{{\"id\":\"first\",\"id\":\"second\",\"ed25519_public_key\":{:?}}}]}}",vec![0x41;32]);
        assert!(parse_release_trust(repeated.as_bytes()).is_err());
    }

    #[test]
    fn invalid_ids_and_non_byte_or_wrong_length_keys_are_rejected() {
        for id in ["", "Uppercase", "1first", "-first", "has space", "nonasciié", "has/slash"] {
            assert!(parse_release_trust(&resource(json!([key(id)]))).is_err(),"accepted invalid ID {id}");
        }
        assert!(parse_release_trust(&resource(json!([key(&"a".repeat(65))]))).is_err());
        for public_key in [json!(vec![0;31]),json!(vec![0;33]),json!("base64-is-not-this-schema"),json!(vec![-1;32]),json!(vec![256;32]),json!(vec![true;32])] {
            assert!(parse_release_trust(&resource(json!([{"id":"valid","ed25519_public_key":public_key}]))).is_err());
        }
    }

    #[test]
    fn future_missing_unknown_and_non_object_schemas_are_rejected() {
        for bytes in [br#"{"schema_version":2,"keys":[]}"#.as_slice(),br#"{"schema_version":0,"keys":[]}"#,
            br#"{"schema_version":true,"keys":[]}"#,br#"{"schema_version":1.0,"keys":[]}"#,br#"{}"#,
            br#"{"schema_version":1,"keys":[],"url":"https://unreviewed.invalid"}"#,br#"[1,[]]"#,b"not-json",b"\xff"] {
            assert!(parse_release_trust(bytes).is_err());
        }
        assert!(parse_release_trust(&resource(json!([["valid",vec![0x41;32]]]))).is_err());
        assert!(parse_release_trust(&resource(json!([{"id":"valid","ed25519_public_key":vec![0x41;32],"header":"secret"}]))).is_err());
    }

    #[test]
    fn byte_and_entry_limits_are_enforced_before_constructing_trust() {
        assert!(parse_release_trust(&vec![b' ';MAX_RELEASE_TRUST_BYTES+1]).is_err());
        let permitted = (0..MAX_RELEASE_TRUST_KEYS).map(|number|key(&format!("a{number:063}"))).collect::<Vec<_>>();
        let mut exact_limit = resource(json!(permitted));
        assert!(exact_limit.len() < MAX_RELEASE_TRUST_BYTES);
        exact_limit.resize(MAX_RELEASE_TRUST_BYTES,b' ');
        assert_eq!(parse_release_trust(&exact_limit).unwrap().len(),MAX_RELEASE_TRUST_KEYS);
        let excessive = (0..=MAX_RELEASE_TRUST_KEYS).map(|number|key(&format!("key-{number}"))).collect::<Vec<_>>();
        let bytes = resource(json!(excessive));
        assert!(bytes.len()<MAX_RELEASE_TRUST_BYTES);
        assert!(parse_release_trust(&bytes).is_err());
    }
}
