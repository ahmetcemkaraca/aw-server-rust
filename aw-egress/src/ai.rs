//! AI-specific validation that still uses the single Egress-owned HTTP transport.

use crate::{PolicyBundleErrorV1, VerifiedPolicyV1};
use aw_models::{
    AIEndpointProfileV1, AIDestinationTypeV1, EgressReasonCodeV1, SignedAIProviderRegistryV1,
};
use ring::digest::{digest, SHA256};
use ring::signature::{self, UnparsedPublicKey};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use url::Url;

const AI_PROVIDER_REGISTRY_DOMAIN: &[u8] = b"PeakActivity:AIProviderRegistryV1\0";
const AI_CUSTOM_DESTINATION_DOMAIN: &[u8] = b"PeakActivity:CustomAIDestinationV1\0";

pub(crate) fn custom_destination_id(profile: &AIEndpointProfileV1) -> String {
    let mut input = AI_CUSTOM_DESTINATION_DOMAIN.to_vec();
    input.extend_from_slice(profile.profile_id.as_bytes());
    input.push(0);
    input.extend_from_slice(profile.origin.as_bytes());
    input.push(0);
    input.extend_from_slice(profile.endpoint_path.as_bytes());
    let hashed = digest(&SHA256, &input);
    let suffix = hashed.as_ref()[..16].iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("ai-custom-{suffix}")
}

/// Checks the user-selected destination class against the resolved address set.
pub fn validate_custom_endpoint_addresses(
    profile: &AIEndpointProfileV1,
    addresses: &[IpAddr],
) -> Result<(), EgressReasonCodeV1> {
    if addresses.is_empty() || addresses.len() > 16 {
        return Err(EgressReasonCodeV1::DestinationRejected);
    }
    if addresses.iter().any(|address| !address_allowed(profile.destination_type, *address)) {
        return Err(EgressReasonCodeV1::DestinationRejected);
    }
    Ok(())
}

pub fn validate_custom_endpoint_pins(
    profile: &AIEndpointProfileV1,
    addresses: &[IpAddr],
) -> Result<(), EgressReasonCodeV1> {
    validate_custom_endpoint_addresses(profile, addresses)?;
    if profile.resolved_addresses.is_empty() {
        return Err(EgressReasonCodeV1::DestinationRejected);
    }
    if !profile.resolved_addresses.is_empty() {
        let expected: Result<Vec<IpAddr>, _> = profile.resolved_addresses.iter().map(|value| value.parse()).collect();
        let mut expected = expected.map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
        let mut actual = addresses.to_vec();
        expected.sort();
        actual.sort();
        expected.dedup();
        actual.dedup();
        if expected != actual {
            return Err(EgressReasonCodeV1::DestinationRejected);
        }
    }
    Ok(())
}

fn address_allowed(destination: AIDestinationTypeV1, address: IpAddr) -> bool {
    if super::proxy::is_public_ip(address) { return true; }
    match address {
        IpAddr::V4(ip) => {
            if ip.is_loopback() { return destination == AIDestinationTypeV1::SelfHosted; }
            if ip.is_private() {
                return matches!(destination,
                    AIDestinationTypeV1::SelfHosted
                        | AIDestinationTypeV1::Lan
                        | AIDestinationTypeV1::PairedDevice
                        | AIDestinationTypeV1::CentralSyncDevice);
            }
            false
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback() { return destination == AIDestinationTypeV1::SelfHosted; }
            if ip.is_unique_local() {
                return matches!(destination,
                    AIDestinationTypeV1::SelfHosted
                        | AIDestinationTypeV1::Lan
                        | AIDestinationTypeV1::PairedDevice
                        | AIDestinationTypeV1::CentralSyncDevice);
            }
            ip.to_ipv4().is_some_and(|ipv4| {
                if ipv4.is_loopback() {
                    destination == AIDestinationTypeV1::SelfHosted
                } else {
                    ipv4.is_private() && matches!(destination,
                        AIDestinationTypeV1::SelfHosted
                            | AIDestinationTypeV1::Lan
                            | AIDestinationTypeV1::PairedDevice
                            | AIDestinationTypeV1::CentralSyncDevice)
                }
            })
        }
    }
}

pub(crate) fn resolve_addresses(profile: &AIEndpointProfileV1) -> Result<(String, u16, Vec<IpAddr>), EgressReasonCodeV1> {
    profile.validate().map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
    let origin = Url::parse(&profile.origin).map_err(|_| EgressReasonCodeV1::DestinationRejected)?;
    let host = origin.host_str().ok_or(EgressReasonCodeV1::DestinationRejected)?.to_string();
    let port = origin.port_or_known_default().ok_or(EgressReasonCodeV1::DestinationRejected)?;
    let resolved = if profile.destination_type == AIDestinationTypeV1::Remote {
        super::proxy::resolve_public_addresses(&host, port)?
    } else {
        (host.as_str(), port).to_socket_addrs()
            .map_err(|_| EgressReasonCodeV1::NetworkUnavailable)?
            .collect::<Vec<_>>()
    };
    let mut addresses = resolved.into_iter().map(|address| address.ip()).collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    validate_custom_endpoint_addresses(profile, &addresses)?;
    Ok((host, port, addresses))
}

pub(crate) fn resolve_pinned_addresses(
    profile: &AIEndpointProfileV1,
) -> Result<Vec<SocketAddr>, EgressReasonCodeV1> {
    if profile.resolved_addresses.is_empty() {
        return Err(EgressReasonCodeV1::DestinationRejected);
    }
    let (host, port, resolved) = resolve_addresses(profile)?;
    validate_custom_endpoint_pins(profile, &resolved)?;
    Ok(resolved.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

/// Canonical, domain-separated bytes for a release-signed Peak AI registry.
pub fn ai_provider_registry_signing_bytes(
    registry: &SignedAIProviderRegistryV1,
) -> Result<Vec<u8>, PolicyBundleErrorV1> {
    registry.validate().map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    let mut providers = registry.providers.clone();
    providers.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    let canonical = serde_json::to_value(&providers).map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    let serialized = serde_json::to_vec(&canonical).map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    let mut message = AI_PROVIDER_REGISTRY_DOMAIN.to_vec();
    message.extend_from_slice(&registry.schema_version.to_be_bytes());
    message.extend_from_slice(&registry.version.to_be_bytes());
    message.extend_from_slice(registry.signer_key_id.as_bytes());
    message.push(0);
    message.extend_from_slice(&serialized);
    Ok(message)
}

pub fn verify_ai_provider_registry(
    registry: &SignedAIProviderRegistryV1,
    trusted_keys: &HashMap<String, Vec<u8>>,
    current_version: Option<u64>,
) -> Result<(), PolicyBundleErrorV1> {
    registry.validate().map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    if current_version.is_some_and(|version| registry.version <= version) {
        return Err(PolicyBundleErrorV1::StaleVersion);
    }
    let key = trusted_keys.get(&registry.signer_key_id).ok_or(PolicyBundleErrorV1::UnknownSigner)?;
    let message = ai_provider_registry_signing_bytes(registry)?;
    UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(&message, &registry.signature)
        .map_err(|_| PolicyBundleErrorV1::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_models::{
        AIAuthenticationV1, AIEndpointProtocolV1, AIProviderV1, EgressDestinationStatusV1, EgressDestinationV1,
        EgressPolicyV1, EgressPurposeV1,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn profile(destination_type: AIDestinationTypeV1, pins: &[&str]) -> AIEndpointProfileV1 {
        AIEndpointProfileV1 {
            profile_id: "profile_01".into(),
            display_name: "test".into(),
            origin: "https://ai.example.invalid".into(),
            endpoint_path: "/v1/chat/completions".into(),
            protocol: AIEndpointProtocolV1::OpenAiChatCompletionsV1,
            authentication: AIAuthenticationV1::None,
            model_id: "model-v1".into(),
            destination_type,
            region_note: "Not verified".into(),
            retention_note: "Not verified".into(),
            training_note: "Not verified".into(),
            cost_note: None,
            credential_ref: None,
            resolved_addresses: pins.iter().map(|value| (*value).into()).collect(),
        }
    }

    fn verified_template() -> VerifiedPolicyV1 {
        VerifiedPolicyV1 {
            policy: EgressPolicyV1 {
                schema_version: 1,
                version: 7,
                hard_deny_version: 1,
                destinations: vec![EgressDestinationV1 {
                    id: "custom-endpoint".into(),
                    status: EgressDestinationStatusV1::Planned,
                    https_origin: None,
                    allowed_purposes: vec!["ai.custom_endpoint".into()],
                }],
                purposes: vec![EgressPurposeV1 {
                    id: "ai.custom_endpoint".into(),
                    destination_id: "custom-endpoint".into(),
                    endpoint_path: "/v1/chat/completions".into(),
                    retention_id: "user-defined".into(),
                    retention_disclosure: "User disclosure is not verified".into(),
                    allowed_fields: vec!["/question".into(), "/aggregate".into()],
                }],
                organization_rules: Vec::new(),
                user_rules: Vec::new(),
                safe_zone_patterns: Vec::new(),
                after_hours: None,
            },
            custom_endpoint: None,
        }
    }

    #[test]
    fn custom_profile_overlays_only_the_signed_generic_ai_destination() {
        let template = verified_template();
        let profile = profile(AIDestinationTypeV1::Remote, &["8.8.8.8"]);
        let active = template.for_custom_endpoint(&profile).unwrap();
        let destination = active.policy().destinations.iter()
            .find(|destination| destination.id == custom_destination_id(&profile)).unwrap();
        assert_eq!(destination.status, EgressDestinationStatusV1::Experimental);
        assert_eq!(destination.https_origin.as_deref(), Some("https://ai.example.invalid"));
        assert_eq!(active.policy().destinations[0].status, EgressDestinationStatusV1::Planned);
        assert!(active.policy().destinations[0].allowed_purposes.is_empty());
        assert_eq!(destination.allowed_purposes, vec!["ai.custom_endpoint".to_string()]);
        assert_eq!(active.custom_endpoint_profile(), Some(&profile));

        let mut changed_path = profile.clone();
        changed_path.endpoint_path = "/unapproved/path".into();
        assert!(template.for_custom_endpoint(&changed_path).is_err());

        let mut missing_purpose = verified_template();
        missing_purpose.policy.purposes.clear();
        assert!(missing_purpose.for_custom_endpoint(&profile).is_err());

        let mut missing_source_field = verified_template();
        missing_source_field.policy.purposes[0].allowed_fields.retain(|field| field != "/aggregate");
        assert!(missing_source_field.for_custom_endpoint(&profile).is_err());
    }

    #[test]
    fn custom_endpoint_address_matrix_matches_the_declared_destination_class() {
        assert!(validate_custom_endpoint_addresses(&profile(AIDestinationTypeV1::Remote, &["8.8.8.8"]), &["8.8.8.8".parse().unwrap()]).is_ok());
        assert!(validate_custom_endpoint_addresses(&profile(AIDestinationTypeV1::Remote, &["10.1.2.3"]), &["10.1.2.3".parse().unwrap()]).is_err());
        assert!(validate_custom_endpoint_addresses(&profile(AIDestinationTypeV1::SelfHosted, &["127.0.0.1"]), &["127.0.0.1".parse().unwrap()]).is_ok());
        assert!(validate_custom_endpoint_addresses(&profile(AIDestinationTypeV1::Lan, &["192.168.1.2"]), &["192.168.1.2".parse().unwrap()]).is_ok());
        assert!(validate_custom_endpoint_addresses(&profile(AIDestinationTypeV1::PairedDevice, &["fc00::2"]), &["fc00::2".parse().unwrap()]).is_ok());
        assert!(validate_custom_endpoint_addresses(&profile(AIDestinationTypeV1::Lan, &["169.254.1.1"]), &["169.254.1.1".parse().unwrap()]).is_err());
        assert!(validate_custom_endpoint_pins(&profile(AIDestinationTypeV1::SelfHosted, &["127.0.0.1"]), &["127.0.0.2".parse().unwrap()]).is_err());
    }

    fn registry() -> SignedAIProviderRegistryV1 {
        SignedAIProviderRegistryV1 {
            schema_version: 1,
            version: 1,
            signer_key_id: "test-key".into(),
            providers: vec![AIProviderV1 {
                provider_id: "provider-test".into(),
                display_name: "Synthetic provider".into(),
                egress_destination_id: "peak-ai-provider".into(),
                egress_purpose_id: "ai.peak".into(),
                model_id: "model-v1".into(),
                model_version: "2026-09".into(),
                region: "test-region".into(),
                retention_id: "retention-test".into(),
                retention_disclosure: "Synthetic test disclosure".into(),
                training_disclosure: "Synthetic test disclosure".into(),
                subprocessors: vec!["Synthetic subprocessor".into()],
                currency_code: "USD".into(),
                input_price_micros_per_1k: 1,
                output_price_micros_per_1k: 2,
                monthly_cap_micros: 100,
            }],
            signature: vec![0; 64],
        }
    }

    #[test]
    fn signed_ai_registry_rejects_tampering_unknown_keys_and_replay() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut registry = registry();
        registry.signature = key.sign(&ai_provider_registry_signing_bytes(&registry).unwrap()).as_ref().to_vec();
        let mut keys = HashMap::new();
        keys.insert("test-key".into(), key.public_key().as_ref().to_vec());
        verify_ai_provider_registry(&registry, &keys, None).unwrap();
        assert_eq!(verify_ai_provider_registry(&registry, &keys, Some(1)), Err(PolicyBundleErrorV1::StaleVersion));
        assert_eq!(verify_ai_provider_registry(&registry, &HashMap::new(), None), Err(PolicyBundleErrorV1::UnknownSigner));
        registry.providers[0].region = "changed-region".into();
        assert_eq!(verify_ai_provider_registry(&registry, &keys, None), Err(PolicyBundleErrorV1::InvalidSignature));
    }

    #[test]
    fn registry_signing_bytes_are_independent_of_provider_list_order() {
        let mut first = registry();
        let mut second_provider = first.providers[0].clone();
        second_provider.provider_id = "provider-alpha".into();
        first.providers.push(second_provider);
        let mut second = first.clone();
        second.providers.reverse();
        assert_eq!(ai_provider_registry_signing_bytes(&first).unwrap(), ai_provider_registry_signing_bytes(&second).unwrap());
    }
}
