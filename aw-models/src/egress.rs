use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressOutcomeV1 {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressApprovalScopeV1 {
    Once,
    TimeLimited,
    DestinationSpecific,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressReasonCodeV1 {
    HardDeny,
    OrganizationRule,
    UserRule,
    UnknownDestination,
    UnknownPurpose,
    UnknownRetention,
    InvalidPolicy,
    InvalidPayload,
    SafeZone,
    AfterHours,
    KillSwitch,
    ApprovalRequired,
    ApprovalExpired,
    PolicyChanged,
    SecretDetected,
    FieldRemoved,
    ValueRedacted,
    UrlReduced,
    PathAliased,
    InvalidSignature,
    DestinationRejected,
    RedirectRejected,
    NetworkUnavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressRequestV1 {
    pub schema_version: u16,
    pub destination_id: String,
    pub purpose_id: String,
    pub retention_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressDecisionV1 {
    pub schema_version: u16,
    pub outcome: EgressOutcomeV1,
    pub sanitized_payload: Option<Value>,
    pub removed_fields: Vec<String>,
    pub reason_codes: Vec<EgressReasonCodeV1>,
    pub policy_version: u64,
    pub preview_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressPreviewV1 {
    pub schema_version: u16,
    pub destination_id: String,
    pub destination_origin: Option<String>,
    pub purpose_id: String,
    pub retention_id: String,
    pub retention_disclosure: Option<String>,
    pub decision: EgressDecisionV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressReceiptV1 {
    pub schema_version: u16,
    pub destination_id: String,
    pub purpose_id: String,
    pub retention_id: String,
    pub allowed_fields: Vec<String>,
    pub policy_version: u64,
    pub scope: EgressApprovalScopeV1,
    pub decision: EgressOutcomeV1,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressApprovalV1 {
    pub schema_version: u16,
    pub approval_id: String,
    pub destination_id: String,
    pub purpose_id: String,
    pub retention_id: String,
    pub policy_version: u64,
    pub scope: EgressApprovalScopeV1,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressContractErrorV1 {
    UnsupportedVersion,
    InvalidDestinationId,
    InvalidPurposeId,
    InvalidRetentionId,
    PayloadMustBeObject,
}

impl fmt::Display for EgressContractErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "Unsupported egress schema version",
            Self::InvalidDestinationId => "Invalid egress destination ID",
            Self::InvalidPurposeId => "Invalid egress purpose ID",
            Self::InvalidRetentionId => "Invalid egress retention ID",
            Self::PayloadMustBeObject => "Egress payload must be a JSON object",
        })
    }
}

impl std::error::Error for EgressContractErrorV1 {}

impl EgressRequestV1 {
    pub fn validate(&self) -> Result<(), EgressContractErrorV1> {
        if self.schema_version != 1 {
            return Err(EgressContractErrorV1::UnsupportedVersion);
        }
        if !valid_identifier(&self.destination_id) {
            return Err(EgressContractErrorV1::InvalidDestinationId);
        }
        if !valid_identifier(&self.purpose_id) {
            return Err(EgressContractErrorV1::InvalidPurposeId);
        }
        if !valid_identifier(&self.retention_id) {
            return Err(EgressContractErrorV1::InvalidRetentionId);
        }
        if !self.payload.is_object() {
            return Err(EgressContractErrorV1::PayloadMustBeObject);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressDestinationStatusV1 {
    Available,
    Beta,
    Experimental,
    Planned,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressMatchKindV1 {
    Field,
    Application,
    Domain,
    Keyword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressRuleActionV1 {
    Deny,
    DropField,
    RedactValue,
    DomainOnly,
    StableAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressPatternV1 {
    pub kind: EgressMatchKindV1,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressRuleV1 {
    pub pattern: EgressPatternV1,
    pub action: EgressRuleActionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressDestinationV1 {
    pub id: String,
    pub status: EgressDestinationStatusV1,
    pub https_origin: Option<String>,
    pub allowed_purposes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressPurposeV1 {
    pub id: String,
    pub destination_id: String,
    pub endpoint_path: String,
    pub retention_id: String,
    pub retention_disclosure: String,
    pub allowed_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AfterHoursV1 {
    /// ISO weekdays: Monday=1 through Sunday=7.
    pub weekdays: Vec<u8>,
    pub start_minute: u16,
    pub end_minute: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicyV1 {
    pub schema_version: u16,
    pub version: u64,
    pub hard_deny_version: u64,
    pub destinations: Vec<EgressDestinationV1>,
    pub purposes: Vec<EgressPurposeV1>,
    pub organization_rules: Vec<EgressRuleV1>,
    pub user_rules: Vec<EgressRuleV1>,
    pub safe_zone_patterns: Vec<EgressPatternV1>,
    pub after_hours: Option<AfterHoursV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicyBundleV1 {
    pub schema_version: u16,
    pub version: u64,
    pub hard_deny_version: u64,
    pub destinations: Vec<EgressDestinationV1>,
    pub purposes: Vec<EgressPurposeV1>,
    pub organization_rules: Vec<EgressRuleV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedEgressPolicyBundleV1 {
    pub schema_version: u16,
    pub signer_key_id: String,
    pub bundle: EgressPolicyBundleV1,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressUserPolicyV1 {
    pub schema_version: u16,
    pub user_rules: Vec<EgressRuleV1>,
    pub safe_zone_patterns: Vec<EgressPatternV1>,
    pub after_hours: Option<AfterHoursV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicyDiffV1 {
    pub schema_version: u16,
    pub from_version: u64,
    pub to_version: u64,
    pub hard_deny_version_before: u64,
    pub hard_deny_version_after: u64,
    pub added_destinations: Vec<EgressDestinationV1>,
    pub removed_destinations: Vec<String>,
    pub changed_destinations: Vec<EgressDestinationV1>,
    pub added_purposes: Vec<EgressPurposeV1>,
    pub removed_purposes: Vec<String>,
    pub changed_purposes: Vec<EgressPurposeV1>,
    pub added_organization_rules: Vec<EgressRuleV1>,
    pub removed_organization_rules: Vec<EgressRuleV1>,
    pub added_user_rules: Vec<EgressRuleV1>,
    pub removed_user_rules: Vec<EgressRuleV1>,
    pub added_safe_zone_patterns: Vec<EgressPatternV1>,
    pub removed_safe_zone_patterns: Vec<EgressPatternV1>,
    pub after_hours_before: Option<AfterHoursV1>,
    pub after_hours_after: Option<AfterHoursV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicyErrorV1 {
    UnsupportedVersion,
    InvalidVersion,
    InvalidDestinationId,
    DuplicateDestinationId,
    InvalidDestinationOrigin,
    InvalidPurposeId,
    InvalidEndpointPath,
    DuplicatePurposeId,
    UnknownDestination,
    DestinationPurposeMismatch,
    InvalidRetentionDisclosure,
    InvalidFieldAllowlist,
    InvalidPattern,
    InvalidSchedule,
}

impl EgressPolicyV1 {
    pub fn from_bundle_and_user(
        bundle: &EgressPolicyBundleV1,
        user: &EgressUserPolicyV1,
    ) -> Result<Self, EgressPolicyErrorV1> {
        if bundle.schema_version != 1 || user.schema_version != 1 {
            return Err(EgressPolicyErrorV1::UnsupportedVersion);
        }
        let policy = Self {
            schema_version: bundle.schema_version,
            version: bundle.version,
            hard_deny_version: bundle.hard_deny_version,
            destinations: bundle.destinations.clone(),
            purposes: bundle.purposes.clone(),
            organization_rules: bundle.organization_rules.clone(),
            user_rules: user.user_rules.clone(),
            safe_zone_patterns: user.safe_zone_patterns.clone(),
            after_hours: user.after_hours.clone(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), EgressPolicyErrorV1> {
        if self.schema_version != 1 {
            return Err(EgressPolicyErrorV1::UnsupportedVersion);
        }
        if self.version == 0 || self.hard_deny_version == 0 {
            return Err(EgressPolicyErrorV1::InvalidVersion);
        }

        let mut destination_ids = std::collections::HashSet::new();
        for destination in &self.destinations {
            if !valid_identifier(&destination.id) {
                return Err(EgressPolicyErrorV1::InvalidDestinationId);
            }
            if !destination_ids.insert(destination.id.as_str()) {
                return Err(EgressPolicyErrorV1::DuplicateDestinationId);
            }
            let needs_origin = matches!(
                destination.status,
                EgressDestinationStatusV1::Available
                    | EgressDestinationStatusV1::Beta
                    | EgressDestinationStatusV1::Experimental
            );
            match (needs_origin, destination.https_origin.as_deref()) {
                (true, Some(origin)) if valid_https_origin(origin) => {}
                (false, None) => {}
                _ => return Err(EgressPolicyErrorV1::InvalidDestinationOrigin),
            }
            let mut purposes = std::collections::HashSet::new();
            if destination.allowed_purposes.iter().any(|purpose| {
                !valid_identifier(purpose) || !purposes.insert(purpose.as_str())
            }) {
                return Err(EgressPolicyErrorV1::InvalidPurposeId);
            }
        }

        let mut purpose_ids = std::collections::HashSet::new();
        for purpose in &self.purposes {
            if !valid_identifier(&purpose.id) {
                return Err(EgressPolicyErrorV1::InvalidPurposeId);
            }
            if !valid_endpoint_path(&purpose.endpoint_path) {
                return Err(EgressPolicyErrorV1::InvalidEndpointPath);
            }
            if !purpose_ids.insert(purpose.id.as_str()) {
                return Err(EgressPolicyErrorV1::DuplicatePurposeId);
            }
            if !valid_identifier(&purpose.retention_id)
                || purpose.retention_disclosure.trim().is_empty()
                || purpose.retention_disclosure.len() > 1024
            {
                return Err(EgressPolicyErrorV1::InvalidRetentionDisclosure);
            }
            if purpose.allowed_fields.iter().any(|field| !valid_field_pointer(field)) {
                return Err(EgressPolicyErrorV1::InvalidFieldAllowlist);
            }
            let Some(destination) = self.destinations.iter().find(|d| d.id == purpose.destination_id) else {
                return Err(EgressPolicyErrorV1::UnknownDestination);
            };
            if !destination.allowed_purposes.iter().any(|id| id == &purpose.id) {
                return Err(EgressPolicyErrorV1::DestinationPurposeMismatch);
            }
        }
        for destination in &self.destinations {
            if destination.allowed_purposes.iter().any(|id| {
                !self.purposes.iter().any(|purpose| {
                    purpose.id == *id && purpose.destination_id == destination.id
                })
            }) {
                return Err(EgressPolicyErrorV1::DestinationPurposeMismatch);
            }
        }

        if self.organization_rules.iter().any(|rule| !valid_pattern(&rule.pattern)) {
            return Err(EgressPolicyErrorV1::InvalidPattern);
        }
        validate_user_policy_fields(&self.user_rules, &self.safe_zone_patterns, self.after_hours.as_ref())?;
        Ok(())
    }
}

impl EgressPolicyBundleV1 {
    pub fn validate(&self) -> Result<(), EgressPolicyErrorV1> {
        let user = EgressUserPolicyV1 {
            schema_version: 1,
            user_rules: Vec::new(),
            safe_zone_patterns: Vec::new(),
            after_hours: None,
        };
        EgressPolicyV1::from_bundle_and_user(self, &user).map(|_| ())
    }
}

impl EgressUserPolicyV1 {
    pub fn validate(&self) -> Result<(), EgressPolicyErrorV1> {
        if self.schema_version != 1 {
            return Err(EgressPolicyErrorV1::UnsupportedVersion);
        }
        validate_user_policy_fields(&self.user_rules, &self.safe_zone_patterns, self.after_hours.as_ref())
    }
}

fn validate_user_policy_fields(
    rules: &[EgressRuleV1],
    safe_zone_patterns: &[EgressPatternV1],
    after_hours: Option<&AfterHoursV1>,
) -> Result<(), EgressPolicyErrorV1> {
    if rules.iter().any(|rule| !valid_pattern(&rule.pattern))
        || safe_zone_patterns.iter().any(|pattern| !valid_pattern(pattern))
    {
        return Err(EgressPolicyErrorV1::InvalidPattern);
    }
    if let Some(schedule) = after_hours {
        let mut weekdays = std::collections::HashSet::new();
        if schedule.weekdays.is_empty()
            || schedule.weekdays.iter().any(|day| !(1..=7).contains(day) || !weekdays.insert(day))
            || schedule.start_minute >= 1440
            || schedule.end_minute >= 1440
            || schedule.start_minute == schedule.end_minute
        {
            return Err(EgressPolicyErrorV1::InvalidSchedule);
        }
    }
    Ok(())
}

fn valid_https_origin(origin: &str) -> bool {
    Url::parse(origin).ok().is_some_and(|url| {
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && matches!(url.path(), "" | "/")
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')))
        })
}

fn valid_pattern(pattern: &EgressPatternV1) -> bool {
    let value = &pattern.value;
    let basic = !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control);
    basic && match pattern.kind {
        EgressMatchKindV1::Field => valid_field_pointer(value),
        EgressMatchKindV1::Domain => valid_domain_pattern(value),
        EgressMatchKindV1::Application | EgressMatchKindV1::Keyword => true,
    }
}

fn valid_domain_pattern(value: &str) -> bool {
    let Ok(url) = Url::parse(&format!("https://{value}")) else { return false; };
    url.host_str().is_some_and(|host| host.eq_ignore_ascii_case(value))
        && matches!(url.path(), "" | "/")
        && url.query().is_none()
        && url.fragment().is_none()
}

fn valid_field_pointer(value: &str) -> bool {
    if !value.starts_with('/') || value.len() > 128 || value.chars().any(char::is_control) { return false; }
    value.split('/').skip(1).all(|segment| {
        if segment.is_empty() { return false; }
        let mut chars = segment.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' && !matches!(chars.next(), Some('0' | '1')) { return false; }
        }
        true
    })
}

fn valid_endpoint_path(value: &str) -> bool {
    if value == "/" { return true; }
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 256
        && !value.chars().any(|ch| matches!(ch, '?' | '#' | '\\' | '%'))
        && !value.chars().any(char::is_control)
        && value.split('/').skip(1).all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn request() -> EgressRequestV1 {
        EgressRequestV1 {
            schema_version: 1,
            destination_id: "sync-relay".into(),
            purpose_id: "sync".into(),
            retention_id: "ephemeral".into(),
            payload: json!({"app": "Editor"}),
        }
    }

    fn policy() -> EgressPolicyV1 {
        EgressPolicyV1 {
            schema_version: 1,
            version: 3,
            hard_deny_version: 1,
            destinations: vec![EgressDestinationV1 {
                id: "sync-relay".into(),
                status: EgressDestinationStatusV1::Available,
                https_origin: Some("https://sync.example".into()),
                allowed_purposes: vec!["sync".into()],
            }],
            purposes: vec![EgressPurposeV1 {
                id: "sync".into(),
                destination_id: "sync-relay".into(),
                endpoint_path: "/sync".into(),
                retention_id: "ephemeral".into(),
                retention_disclosure: "Session only".into(),
                allowed_fields: vec!["/timestamp".into(), "/app".into()],
            }],
            organization_rules: vec![],
            user_rules: vec![],
            safe_zone_patterns: vec![],
            after_hours: None,
        }
    }

    fn bundle() -> EgressPolicyBundleV1 {
        let policy = policy();
        EgressPolicyBundleV1 {
            schema_version: 1,
            version: policy.version,
            hard_deny_version: policy.hard_deny_version,
            destinations: policy.destinations,
            purposes: policy.purposes,
            organization_rules: policy.organization_rules,
        }
    }

    fn receipt() -> EgressReceiptV1 {
        EgressReceiptV1 {
            schema_version: 1,
            destination_id: "sync-relay".into(),
            purpose_id: "sync".into(),
            retention_id: "ephemeral".into(),
            allowed_fields: vec!["timestamp".into(), "app".into()],
            policy_version: 3,
            scope: EgressApprovalScopeV1::Once,
            decision: EgressOutcomeV1::Allow,
            created_at: DateTime::parse_from_rfc3339("2026-09-23T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn request_rejects_a_schema_version_it_does_not_understand() {
        let mut req = request();
        req.schema_version = 2;
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_requires_canonical_ids_and_an_object_payload() {
        assert!(request().validate().is_ok());
        let mut req = request();
        req.destination_id = "sync relay".into();
        assert!(req.validate().is_err());
        let mut req = request();
        req.purpose_id.clear();
        assert!(req.validate().is_err());
        let mut req = request();
        req.payload = json!("unstructured payload");
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_rejects_fields_from_an_unrecognized_contract_shape() {
        let mut request = serde_json::to_value(request()).unwrap();
        request["unexpected"] = json!(true);
        assert!(serde_json::from_value::<EgressRequestV1>(request).is_err());
    }

    #[test]
    fn policy_requires_unique_registry_ids_and_consistent_references() {
        assert!(policy().validate().is_ok());
        let mut p = policy();
        p.hard_deny_version = 0;
        assert!(p.validate().is_err());
        let mut p = policy();
        p.purposes[0].destination_id = "unknown".into();
        assert!(p.validate().is_err());
        let mut p = policy();
        p.destinations.push(p.destinations[0].clone());
        assert!(p.validate().is_err());
    }

    #[test]
    fn purpose_field_allowlist_requires_json_pointer_paths() {
        let mut p = policy();
        p.purposes[0].allowed_fields = vec!["app".into()];
        assert!(p.validate().is_err());
    }

    #[test]
    fn field_rules_require_json_pointer_paths() {
        let mut p = policy();
        p.user_rules.push(EgressRuleV1 {
            pattern: EgressPatternV1 { kind: EgressMatchKindV1::Field, value: "url".into() },
            action: EgressRuleActionV1::DropField,
        });
        assert!(p.validate().is_err());
    }

    #[test]
    fn signed_bundle_contains_registry_and_organization_policy_only() {
        let value = serde_json::to_value(bundle()).unwrap();
        assert!(value.get("destinations").is_some());
        assert!(value.get("purposes").is_some());
        assert!(value.get("organization_rules").is_some());
        assert!(value.get("user_rules").is_none());
        assert!(value.get("safe_zone_patterns").is_none());
    }

    #[test]
    fn active_policy_merges_local_user_rules_without_changing_signed_registry() {
        let bundle = bundle();
        let user = EgressUserPolicyV1 {
            schema_version: 1,
            user_rules: vec![EgressRuleV1 {
                pattern: EgressPatternV1 { kind: EgressMatchKindV1::Field, value: "/app".into() },
                action: EgressRuleActionV1::DropField,
            }],
            safe_zone_patterns: vec![],
            after_hours: None,
        };
        let active = EgressPolicyV1::from_bundle_and_user(&bundle, &user).unwrap();
        assert_eq!(active.destinations, bundle.destinations);
        assert_eq!(active.user_rules, user.user_rules);
    }

    #[test]
    fn purpose_registry_carries_an_explicit_field_allowlist() {
        let serialized = serde_json::to_value(policy()).unwrap();
        assert_eq!(serialized["purposes"][0]["allowed_fields"], json!(["/timestamp", "/app"]));
    }

    #[test]
    fn available_destinations_require_an_exact_https_origin() {
        let mut p = policy();
        p.destinations[0].https_origin = Some("http://sync.example".into());
        assert!(p.validate().is_err());
        let mut p = policy();
        p.destinations[0].https_origin = Some("https://user@sync.example/path".into());
        assert!(p.validate().is_err());
    }

    #[test]
    fn purpose_endpoint_path_is_relative_and_has_no_query_or_traversal() {
        let mut p = policy();
        p.purposes[0].endpoint_path = "/api/v1/sync".into();
        assert!(p.validate().is_ok());
        p.purposes[0].endpoint_path = "/api/../admin".into();
        assert!(p.validate().is_err());
        p.purposes[0].endpoint_path = "/api/v1/sync?destination=other".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn planned_destinations_cannot_have_an_origin() {
        let mut p = policy();
        p.destinations[0].status = EgressDestinationStatusV1::Planned;
        p.destinations[0].https_origin = Some("not a URL".into());
        assert!(p.validate().is_err());
    }

    #[test]
    fn keyword_patterns_accept_spaces_but_registry_purpose_refs_must_match() {
        let mut p = policy();
        p.user_rules.push(EgressRuleV1 {
            pattern: EgressPatternV1 { kind: EgressMatchKindV1::Keyword, value: "medical visit".into() },
            action: EgressRuleActionV1::DropField,
        });
        assert!(p.validate().is_ok());
        let mut p = policy();
        p.destinations[0].allowed_purposes.push("other".into());
        assert!(p.validate().is_err());
    }

    #[test]
    fn receipt_serializes_only_content_free_metadata() {
        let value = serde_json::to_value(receipt()).unwrap();
        assert!(value.get("payload").is_none());
        assert!(value.get("sanitized_payload").is_none());
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["scope"], "once");
    }

    #[test]
    fn generated_schema_covers_versions_and_purpose_allowlists() {
        let schema: Value = serde_json::from_str(include_str!("../../schemas/egress-v1.json")).unwrap();
        let definitions = schema["oneOf"].as_array().unwrap();
        let find = |title: &str| definitions.iter().find(|item| item["title"] == title).unwrap();
        assert_eq!(find("EgressRequestV1")["properties"]["schema_version"]["const"], 1);
        let approval = find("EgressApprovalV1");
        assert_eq!(approval["properties"]["schema_version"]["const"], 1);
        assert!(approval["properties"]["payload_tag"].is_null());
        let policy = find("EgressPolicyV1");
        assert_eq!(policy["properties"]["schema_version"]["const"], 1);
        assert!(policy["definitions"]["EgressPurposeV1"]["properties"]["allowed_fields"].is_object());
        let diff = find("EgressPolicyDiffV1");
        assert!(diff["properties"]["from_version"].is_object());
        assert!(diff["properties"]["payload"].is_null());
    }

    #[test]
    fn reason_codes_have_stable_snake_case_names_and_reject_unknown_values() {
        assert_eq!(serde_json::to_value(EgressReasonCodeV1::HardDeny).unwrap(), "hard_deny");
        assert_eq!(serde_json::to_value(EgressReasonCodeV1::FieldRemoved).unwrap(), "field_removed");
        assert!(serde_json::from_value::<EgressReasonCodeV1>(json!("unknown_reason")).is_err());
    }
}
