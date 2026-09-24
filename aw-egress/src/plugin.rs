//! Checks plugin network grants against the already verified outbound policy.
use crate::VerifiedPolicyV1;
use aw_models::{EgressDestinationStatusV1, PluginManifestV1};
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginEgressGrantErrorV1 { InvalidManifest, InvalidGrant }

/// Plugin grants may only narrow signed Egress destinations and purposes.
pub fn validate_plugin_egress_grants_v1(
    manifest: &PluginManifestV1,
    policy: &VerifiedPolicyV1,
) -> Result<(), PluginEgressGrantErrorV1> {
    manifest.validate().map_err(|_| PluginEgressGrantErrorV1::InvalidManifest)?;
    for grant in &manifest.capabilities.network {
        let destination = policy.policy().destinations.iter()
            .find(|destination| destination.id == grant.destination_id)
            .ok_or(PluginEgressGrantErrorV1::InvalidGrant)?;
        if !matches!(destination.status, EgressDestinationStatusV1::Available | EgressDestinationStatusV1::Beta | EgressDestinationStatusV1::Experimental)
            || !destination.allowed_purposes.iter().any(|purpose| purpose == &grant.purpose_id)
        {
            return Err(PluginEgressGrantErrorV1::InvalidGrant);
        }
        let origin = destination.https_origin.as_deref().ok_or(PluginEgressGrantErrorV1::InvalidGrant)?;
        let url = Url::parse(origin).map_err(|_| PluginEgressGrantErrorV1::InvalidGrant)?;
        if url.scheme() != "https" || url.host_str() != Some(grant.domain.as_str())
            || !url.username().is_empty() || url.password().is_some()
            || !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some()
            || !policy.policy().purposes.iter().any(|purpose| {
                purpose.id == grant.purpose_id && purpose.destination_id == grant.destination_id
            })
        {
            return Err(PluginEgressGrantErrorV1::InvalidGrant);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VerifiedPolicyV1;
    use aw_models::{
        EgressDestinationV1, EgressPolicyV1, EgressPurposeV1, PluginCapabilitiesV1,
        PluginManifestV1, PluginNetworkCapabilityV1, PluginPayloadClassV1,
    };

    #[test]
    fn plugin_network_grant_must_match_an_available_signed_egress_purpose() {
        let mut manifest = PluginManifestV1 {
            schema_version: 1, plugin_id: "sample-plugin".into(), version: "1.0.0".into(),
            publisher_key_id: "publisher-01".into(), display_name: "Sample".into(),
            description: String::new(), capabilities: PluginCapabilitiesV1::default(),
        };
        manifest.capabilities.network.push(PluginNetworkCapabilityV1 {
            domain: "api.example.net".into(), destination_id: "vendor-api".into(),
            purpose_id: "plugin.export".into(), payload_class: PluginPayloadClassV1::Aggregate,
        });
        let policy = VerifiedPolicyV1 {
            policy: EgressPolicyV1 {
                schema_version: 1, version: 1, hard_deny_version: 1,
                destinations: vec![EgressDestinationV1 {
                    id: "vendor-api".into(), status: EgressDestinationStatusV1::Available,
                    https_origin: Some("https://api.example.net".into()), allowed_purposes: vec!["plugin.export".into()],
                }],
                purposes: vec![EgressPurposeV1 {
                    id: "plugin.export".into(), destination_id: "vendor-api".into(),
                    endpoint_path: "/v1/export".into(), retention_id: "bounded".into(),
                    retention_disclosure: "synthetic".into(), allowed_fields: vec!["/aggregate".into()],
                }],
                organization_rules: vec![], user_rules: vec![], safe_zone_patterns: vec![], after_hours: None,
            },
            custom_endpoint: None,
        };
        assert!(validate_plugin_egress_grants_v1(&manifest, &policy).is_ok());
        manifest.capabilities.network[0].domain = "other.example.net".into();
        assert_eq!(validate_plugin_egress_grants_v1(&manifest, &policy), Err(PluginEgressGrantErrorV1::InvalidGrant));
    }
}
