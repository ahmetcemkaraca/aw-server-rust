//! Deterministic outbound privacy policy evaluation and transport boundary.

use aw_models::{
    AIEndpointProfileV1, AfterHoursV1, EgressDecisionV1, EgressDestinationStatusV1,
    EgressOutcomeV1, EgressPatternV1, EgressPolicyDiffV1, EgressPolicyV1, EgressReasonCodeV1,
    EgressRequestV1, EgressRuleActionV1, EgressRuleV1, EgressMatchKindV1,
    EgressUserPolicyV1, SignedEgressPolicyBundleV1,
};
use chrono::{DateTime, Datelike, FixedOffset, Timelike, Utc};
use regex::Regex;
use ring::hmac;
use ring::signature::{self, UnparsedPublicKey};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::OnceLock;
use url::Url;

pub const SUPPORTED_HARD_DENY_VERSION_V1: u64 = 1;
static DLP_PATTERNS: OnceLock<Result<(Vec<Regex>, Regex), ()>> = OnceLock::new();

pub struct EvaluationContext<'a> {
    pub now_utc: DateTime<Utc>,
    pub local_offset_seconds: i32,
    pub alias_secret: &'a [u8],
    pub preview_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyBundleErrorV1 {
    UnsupportedVersion,
    InvalidPolicy,
    UnknownSigner,
    InvalidSignature,
    StaleVersion,
    HardDenyRollback,
}

#[derive(Debug, Clone)]
pub struct VerifiedPolicyV1 {
    policy: EgressPolicyV1,
    custom_endpoint: Option<AIEndpointProfileV1>,
}

impl VerifiedPolicyV1 {
    pub fn policy(&self) -> &EgressPolicyV1 { &self.policy }

    pub fn for_custom_endpoint(
        &self,
        profile: &AIEndpointProfileV1,
    ) -> Result<Self, EgressReasonCodeV1> {
        self.overlay_custom_endpoint(profile, true)
    }

    pub(crate) fn for_custom_endpoint_probe(
        &self,
        profile: &AIEndpointProfileV1,
    ) -> Result<Self, EgressReasonCodeV1> {
        self.overlay_custom_endpoint(profile, false)
    }

    fn overlay_custom_endpoint(
        &self,
        profile: &AIEndpointProfileV1,
        require_pins: bool,
    ) -> Result<Self, EgressReasonCodeV1> {
        if profile.validate().is_err()
            || (require_pins && profile.resolved_addresses.is_empty())
        {
            return Err(EgressReasonCodeV1::DestinationRejected);
        }
        if !profile.resolved_addresses.is_empty() {
            let pins = profile.resolved_addresses.iter()
                .map(|address| address.parse().map_err(|_| EgressReasonCodeV1::DestinationRejected))
                .collect::<Result<Vec<std::net::IpAddr>, _>>()?;
            validate_custom_endpoint_addresses(profile, &pins)?;
        }
        let purpose_id = "ai.custom_endpoint";
        let destination_id = "custom-endpoint";
        let mut policy = self.policy.clone();
        let destination = policy.destinations.iter()
            .find(|destination| destination.id == destination_id)
            .cloned()
            .ok_or(EgressReasonCodeV1::UnknownDestination)?;
        if destination.status != EgressDestinationStatusV1::Planned
            || destination.https_origin.is_some()
            || !destination.allowed_purposes.iter().any(|value| value == purpose_id)
        {
            return Err(EgressReasonCodeV1::InvalidPolicy);
        }
        let purpose = policy.purposes.iter()
            .find(|purpose| purpose.id == purpose_id && purpose.destination_id == destination_id)
            .ok_or(EgressReasonCodeV1::UnknownPurpose)?;
        if purpose.endpoint_path != profile.endpoint_path {
            return Err(EgressReasonCodeV1::DestinationRejected);
        }
        if !purpose.allowed_fields.iter().any(|field| field == "/question")
            || !purpose.allowed_fields.iter().any(|field| field == "/aggregate")
        { return Err(EgressReasonCodeV1::InvalidPolicy); }
        let dynamic_id = ai::custom_destination_id(profile);
        if policy.destinations.iter().any(|item| item.id == dynamic_id) {
            return Err(EgressReasonCodeV1::InvalidPolicy);
        }
        let mut dynamic_destination = destination;
        dynamic_destination.id = dynamic_id.clone();
        dynamic_destination.status = EgressDestinationStatusV1::Experimental;
        dynamic_destination.https_origin = Some(profile.origin.clone());
        dynamic_destination.allowed_purposes = vec![purpose_id.to_string()];
        let template = policy.destinations.iter_mut()
            .find(|item| item.id == destination_id)
            .ok_or(EgressReasonCodeV1::UnknownDestination)?;
        template.allowed_purposes.retain(|value| value != purpose_id);
        let purpose = policy.purposes.iter_mut().find(|item| item.id == purpose_id)
            .ok_or(EgressReasonCodeV1::UnknownPurpose)?;
        purpose.destination_id = dynamic_id;
        policy.destinations.push(dynamic_destination);
        policy.validate().map_err(|_| EgressReasonCodeV1::InvalidPolicy)?;
        Ok(Self { policy, custom_endpoint: Some(profile.clone()) })
    }

    pub fn custom_endpoint_profile(&self) -> Option<&AIEndpointProfileV1> {
        self.custom_endpoint.as_ref()
    }

    pub fn custom_endpoint_destination_id(&self) -> Option<String> {
        self.custom_endpoint.as_ref().map(ai::custom_destination_id)
    }
}

/// Bytes signed by policy publishers. The signature itself is excluded.
pub fn policy_bundle_signing_bytes(
    signed: &SignedEgressPolicyBundleV1,
) -> Result<Vec<u8>, PolicyBundleErrorV1> {
    if signed.schema_version != 1 || !valid_key_id(&signed.signer_key_id) {
        return Err(PolicyBundleErrorV1::UnsupportedVersion);
    }
    signed.bundle.validate().map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    let canonical = serde_json::to_value(&signed.bundle).map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    let serialized = serde_json::to_vec(&canonical).map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    let mut message = b"PeakActivity:EgressPolicyBundleV1\0".to_vec();
    message.extend_from_slice(&signed.schema_version.to_be_bytes());
    message.extend_from_slice(signed.signer_key_id.as_bytes());
    message.push(0);
    message.extend_from_slice(&serialized);
    Ok(message)
}

/// Verifies the release-owned bundle, then merges only restrictive local rules.
/// An empty trusted-key map disables signed bundle activation.
pub fn verify_and_activate(
    signed: &SignedEgressPolicyBundleV1,
    user: &EgressUserPolicyV1,
    trusted_keys: &HashMap<String, Vec<u8>>,
    current: Option<&EgressPolicyV1>,
) -> Result<VerifiedPolicyV1, PolicyBundleErrorV1> {
    if signed.schema_version != 1 || user.schema_version != 1 {
        return Err(PolicyBundleErrorV1::UnsupportedVersion);
    }
    signed.bundle.validate().map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    if let Some(current) = current {
        if signed.bundle.version <= current.version { return Err(PolicyBundleErrorV1::StaleVersion); }
        if signed.bundle.hard_deny_version < current.hard_deny_version {
            return Err(PolicyBundleErrorV1::HardDenyRollback);
        }
    }
    if signed.bundle.hard_deny_version > SUPPORTED_HARD_DENY_VERSION_V1 {
        return Err(PolicyBundleErrorV1::UnsupportedVersion);
    }
    if signed.signature.len() != 64 { return Err(PolicyBundleErrorV1::InvalidSignature); }
    let public_key = trusted_keys.get(&signed.signer_key_id).ok_or(PolicyBundleErrorV1::UnknownSigner)?;
    let message = policy_bundle_signing_bytes(signed)?;
    UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&message, &signed.signature)
        .map_err(|_| PolicyBundleErrorV1::InvalidSignature)?;
    let policy = EgressPolicyV1::from_bundle_and_user(&signed.bundle, user)
        .map_err(|_| PolicyBundleErrorV1::InvalidPolicy)?;
    Ok(VerifiedPolicyV1 { policy, custom_endpoint: None })
}

pub fn policy_diff(previous: &EgressPolicyV1, next: &EgressPolicyV1) -> EgressPolicyDiffV1 {
    let (added_destinations, removed_destinations, changed_destinations) =
        diff_by_id(&previous.destinations, &next.destinations, |value| value.id.clone());
    let (added_purposes, removed_purposes, changed_purposes) =
        diff_by_id(&previous.purposes, &next.purposes, |value| value.id.clone());
    let (added_organization_rules, removed_organization_rules) =
        diff_items(&previous.organization_rules, &next.organization_rules);
    let (added_user_rules, removed_user_rules) = diff_items(&previous.user_rules, &next.user_rules);
    let (added_safe_zone_patterns, removed_safe_zone_patterns) =
        diff_items(&previous.safe_zone_patterns, &next.safe_zone_patterns);
    EgressPolicyDiffV1 {
        schema_version: 1,
        from_version: previous.version,
        to_version: next.version,
        hard_deny_version_before: previous.hard_deny_version,
        hard_deny_version_after: next.hard_deny_version,
        added_destinations,
        removed_destinations,
        changed_destinations,
        added_purposes,
        removed_purposes,
        changed_purposes,
        added_organization_rules,
        removed_organization_rules,
        added_user_rules,
        removed_user_rules,
        added_safe_zone_patterns,
        removed_safe_zone_patterns,
        after_hours_before: previous.after_hours.clone(),
        after_hours_after: next.after_hours.clone(),
    }
}

fn diff_by_id<T: Clone + PartialEq>(
    previous: &[T],
    next: &[T],
    id: impl Fn(&T) -> String,
) -> (Vec<T>, Vec<String>, Vec<T>) {
    let previous_by_id: HashMap<String, &T> = previous.iter().map(|item| (id(item), item)).collect();
    let next_by_id: HashMap<String, &T> = next.iter().map(|item| (id(item), item)).collect();
    let mut added: Vec<T> = next.iter().filter(|item| !previous_by_id.contains_key(&id(item)))
        .cloned().collect();
    let mut removed: Vec<String> = previous_by_id.keys()
        .filter(|key| !next_by_id.contains_key(*key)).cloned().collect();
    let mut changed: Vec<T> = next.iter().filter(|item| {
        previous_by_id.get(&id(item)).is_some_and(|old| **old != **item)
    }).cloned().collect();
    added.sort_by_key(|item| id(item));
    removed.sort();
    changed.sort_by_key(|item| id(item));
    (added, removed, changed)
}

fn diff_items<T: Clone + PartialEq + serde::Serialize>(previous: &[T], next: &[T]) -> (Vec<T>, Vec<T>) {
    let mut added: Vec<T> = next.iter().filter(|item| !previous.contains(item)).cloned().collect();
    let mut removed: Vec<T> = previous.iter().filter(|item| !next.contains(item)).cloned().collect();
    added.sort_by_key(|item| serde_json::to_string(item).unwrap_or_default());
    removed.sort_by_key(|item| serde_json::to_string(item).unwrap_or_default());
    (added, removed)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')))
        })
}

pub fn evaluate(
    request: &EgressRequestV1,
    policy: &EgressPolicyV1,
    context: &EvaluationContext<'_>,
) -> EgressDecisionV1 {
    let policy_version = policy.version;
    if request.validate().is_err() {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::InvalidPayload);
    }
    if policy.validate().is_err() {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::InvalidPolicy);
    }
    if policy.hard_deny_version != SUPPORTED_HARD_DENY_VERSION_V1 {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::InvalidPolicy);
    }
    if context.preview_id.is_empty()
        || context.preview_id.len() > 128
        || context.local_offset_seconds.unsigned_abs() >= 86_400
    {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::InvalidPolicy);
    }
    if has_secret(&request.payload).unwrap_or(true) {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::SecretDetected);
    }

    let Some(destination) = policy.destinations.iter().find(|item| item.id == request.destination_id) else {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::UnknownDestination);
    };
    if !matches!(destination.status,
        EgressDestinationStatusV1::Available
            | EgressDestinationStatusV1::Beta
            | EgressDestinationStatusV1::Experimental)
    {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::UnknownDestination);
    }
    let Some(purpose) = policy.purposes.iter().find(|item| item.id == request.purpose_id) else {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::UnknownPurpose);
    };
    if purpose.destination_id != request.destination_id {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::UnknownPurpose);
    }
    if purpose.retention_id != request.retention_id {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::UnknownRetention);
    }
    if policy.after_hours.as_ref().is_some_and(|schedule| is_after_hours(schedule, context)) {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::AfterHours);
    }
    if policy.safe_zone_patterns.iter().any(|pattern| matches_any(&request.payload, pattern)) {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::SafeZone);
    }

    let mut payload = request.payload.clone();
    let mut removed_fields = Vec::new();
    let mut reason_codes = Vec::new();
    for (rules, reason) in [
        (policy.user_rules.as_slice(), EgressReasonCodeV1::UserRule),
        (policy.organization_rules.as_slice(), EgressReasonCodeV1::OrganizationRule),
    ] {
        for rule in rules {
            let old_payload = payload.clone();
            let old_removed_len = removed_fields.len();
            match apply_rule(payload, rule, reason, context, &mut removed_fields) {
                Ok(updated) => payload = updated,
                Err(code) => return deny(policy_version, context.preview_id, code),
            }
            let matched = payload != old_payload || removed_fields.len() != old_removed_len;
            if removed_fields.len() != old_removed_len {
                push_reason(&mut reason_codes, EgressReasonCodeV1::FieldRemoved);
            }
            if matched && rule.action == EgressRuleActionV1::RedactValue {
                push_reason(&mut reason_codes, EgressReasonCodeV1::ValueRedacted);
            } else if matched && rule.action == EgressRuleActionV1::DomainOnly {
                push_reason(&mut reason_codes, EgressReasonCodeV1::UrlReduced);
            } else if matched && rule.action == EgressRuleActionV1::StableAlias {
                push_reason(&mut reason_codes, EgressReasonCodeV1::PathAliased);
            }
        }
    }

    let Some(object) = payload.as_object() else {
        return deny(policy_version, context.preview_id, EgressReasonCodeV1::InvalidPayload);
    };
    let mut filtered = Map::new();
    let mut field_removed = false;
    for (key, value) in object {
        let path = format!("/{}", escape_pointer(key));
        match filter_allowed(value, &path, &purpose.allowed_fields, &mut removed_fields) {
            Some(value) => { filtered.insert(key.clone(), value); }
            None => { field_removed = true; }
        }
    }
    if field_removed {
        push_reason(&mut reason_codes, EgressReasonCodeV1::FieldRemoved);
    }
    removed_fields.sort();
    removed_fields.dedup();

    EgressDecisionV1 {
        schema_version: 1,
        outcome: EgressOutcomeV1::Allow,
        sanitized_payload: Some(Value::Object(filtered)),
        removed_fields,
        reason_codes,
        policy_version,
        preview_id: context.preview_id.to_string(),
    }
}

mod ai;
pub use ai::{
    ai_provider_registry_signing_bytes, validate_custom_endpoint_addresses,
    validate_custom_endpoint_pins, verify_ai_provider_registry,
};

mod proxy;
pub use proxy::{ApprovedEgress, EgressProxy, EgressSendGuard, EgressTransport, EgressUserPolicyPreview};

mod plugin;
pub use plugin::{
    validate_plugin_egress_grants_v1, PluginEgressGrantErrorV1,
};

#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
mod sync;
#[cfg(any(feature = "encryption", feature = "encryption-vendored"))]
pub use sync::EgressSyncRelayTransportV1;

#[cfg(all(test, any(feature = "encryption", feature = "encryption-vendored")))]
mod sync_tests;

fn deny(policy_version: u64, preview_id: &str, reason: EgressReasonCodeV1) -> EgressDecisionV1 {
    EgressDecisionV1 {
        schema_version: 1,
        outcome: EgressOutcomeV1::Deny,
        sanitized_payload: None,
        removed_fields: Vec::new(),
        reason_codes: vec![reason],
        policy_version,
        preview_id: preview_id.to_string(),
    }
}

fn push_reason(reasons: &mut Vec<EgressReasonCodeV1>, reason: EgressReasonCodeV1) {
    if !reasons.contains(&reason) { reasons.push(reason); }
}

fn has_secret(payload: &Value) -> Result<bool, ()> {
    let mut strings = Vec::new();
    if collect_sensitive_values(payload, &mut strings) { return Ok(true); }
    let joined = strings.join("");
    let compact: String = joined.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect();
    let (patterns, compact_regex) = DLP_PATTERNS.get_or_init(|| {
        let patterns = [
            r"(?i)(?:sk_(?:live|test)_|gh[pousr]_|github_pat_|xox[baprs]-)[A-Za-z0-9_\-]{8,}",
            r"AKIA[0-9A-Z]{16}",
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        ].iter().map(|pattern| Regex::new(pattern).map_err(|_| ())).collect::<Result<Vec<_>, _>>()?;
        let compact = Regex::new(r"(?:sklive|sktest|gh[pousr]|githubpat)[a-z0-9]{8,}").map_err(|_| ())?;
        Ok((patterns, compact))
    }).as_ref().map_err(|_| ())?;
    if patterns.iter().any(|regex| regex.is_match(&joined)) { return Ok(true); }
    Ok(compact_regex.is_match(&compact))
}

fn collect_sensitive_values(value: &Value, strings: &mut Vec<String>) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, child)| {
            let normalized: String = key.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect();
            let sensitive = ["password", "secret", "credential", "authorization", "apikey", "token", "privatekey"]
                .iter().any(|needle| normalized.contains(needle));
            sensitive || collect_sensitive_values(child, strings)
        }),
        Value::Array(items) => items.iter().any(|item| collect_sensitive_values(item, strings)),
        Value::String(text) => { strings.push(text.clone()); false }
        _ => false,
    }
}

fn is_after_hours(schedule: &AfterHoursV1, context: &EvaluationContext<'_>) -> bool {
    let Some(offset) = FixedOffset::east_opt(context.local_offset_seconds) else { return true; };
    let local = context.now_utc.with_timezone(&offset);
    let minute = (local.hour() * 60 + local.minute()) as u16;
    let day = local.weekday().number_from_monday() as u8;
    let previous_day = if day == 1 { 7 } else { day - 1 };
    let has_day = |value| schedule.weekdays.contains(&value);
    if schedule.start_minute < schedule.end_minute {
        has_day(day) && minute >= schedule.start_minute && minute < schedule.end_minute
    } else {
        (has_day(day) && minute >= schedule.start_minute)
            || (has_day(previous_day) && minute < schedule.end_minute)
    }
}

fn matches_any(value: &Value, pattern: &EgressPatternV1) -> bool {
    matches_at(value, "", pattern)
}

fn matches_at(value: &Value, path: &str, pattern: &EgressPatternV1) -> bool {
    if pattern_matches_value(path, value, pattern) { return true; }
    match value {
        Value::Object(object) => object.iter().any(|(key, child)| {
            matches_at(child, &format!("{path}/{}", escape_pointer(key)), pattern)
        }),
        Value::Array(items) => items.iter().enumerate().any(|(index, child)| {
            matches_at(child, &format!("{path}/{index}"), pattern)
        }),
        _ => false,
    }
}

fn pattern_matches_value(path: &str, value: &Value, pattern: &EgressPatternV1) -> bool {
    if pattern.kind == EgressMatchKindV1::Field {
        return path == pattern.value;
    }
    let Some(text) = value.as_str() else { return false; };
    match pattern.kind {
        EgressMatchKindV1::Field => path == pattern.value,
        EgressMatchKindV1::Application => {
            path.rsplit('/').next().is_some_and(|key| matches!(key, "app" | "application"))
                && text.to_lowercase().contains(&pattern.value.to_lowercase())
        }
        EgressMatchKindV1::Domain => domain_matches(text, &pattern.value),
        EgressMatchKindV1::Keyword => text.to_lowercase().contains(&pattern.value.to_lowercase()),
    }
}

fn domain_matches(value: &str, pattern: &str) -> bool {
    let Ok(url) = Url::parse(value) else { return false; };
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case(pattern)
            || host.to_ascii_lowercase().ends_with(&format!(".{}", pattern.to_ascii_lowercase()))
    })
}

fn apply_rule(
    value: Value,
    rule: &EgressRuleV1,
    deny_reason: EgressReasonCodeV1,
    context: &EvaluationContext<'_>,
    removed: &mut Vec<String>,
) -> Result<Value, EgressReasonCodeV1> {
    let updated = transform_rule(value, "", rule, deny_reason, context, removed)?;
    Ok(updated.unwrap_or(Value::Null))
}

fn transform_rule(
    value: Value,
    path: &str,
    rule: &EgressRuleV1,
    deny_reason: EgressReasonCodeV1,
    context: &EvaluationContext<'_>,
    removed: &mut Vec<String>,
) -> Result<Option<Value>, EgressReasonCodeV1> {
    if pattern_matches_value(path, &value, &rule.pattern) {
        return match rule.action {
            EgressRuleActionV1::Deny => Err(deny_reason),
            EgressRuleActionV1::DropField => {
                removed.push(path.to_string());
                Ok(None)
            }
            EgressRuleActionV1::RedactValue => Ok(Some(Value::String("[REDACTED]".into()))),
            EgressRuleActionV1::DomainOnly => {
                let Some(text) = value.as_str() else { return Err(EgressReasonCodeV1::InvalidPayload); };
                Ok(Some(Value::String(domain_only(text).ok_or(EgressReasonCodeV1::InvalidPayload)?)))
            }
            EgressRuleActionV1::StableAlias => {
                let Some(text) = value.as_str() else { return Err(EgressReasonCodeV1::InvalidPayload); };
                if context.alias_secret.len() < 16 { return Err(EgressReasonCodeV1::InvalidPolicy); }
                Ok(Some(Value::String(stable_alias(text, context.alias_secret))))
            }
        };
    }
    match value {
        Value::Object(object) => {
            let mut output = Map::new();
            for (key, child) in object {
                let child_path = format!("{path}/{}", escape_pointer(&key));
                if let Some(child) = transform_rule(child, &child_path, rule, deny_reason, context, removed)? {
                    output.insert(key, child);
                }
            }
            Ok(Some(Value::Object(output)))
        }
        Value::Array(items) => {
            let mut output = Vec::new();
            for (index, child) in items.into_iter().enumerate() {
                let child_path = format!("{path}/{index}");
                if let Some(child) = transform_rule(child, &child_path, rule, deny_reason, context, removed)? {
                    output.push(child);
                }
            }
            Ok(Some(Value::Array(output)))
        }
        value => Ok(Some(value)),
    }
}

fn domain_only(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() { return None; }
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Some(url.origin().ascii_serialization())
}

fn stable_alias(value: &str, secret: &[u8]) -> String {
    if is_verified_alias(value, secret) { return value.to_string(); }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut message = b"path:v1\0".to_vec();
    message.extend_from_slice(value.as_bytes());
    let digest = to_hex(&hmac::sign(&key, &message).as_ref()[..12]);
    let tag = to_hex(hmac::sign(&key, format!("alias:v1:{digest}").as_bytes()).as_ref());
    format!("local:v1:{digest}:{tag}")
}

fn is_verified_alias(value: &str, secret: &[u8]) -> bool {
    let Some(encoded) = value.strip_prefix("local:v1:") else { return false; };
    let Some((digest, tag)) = encoded.split_once(':') else { return false; };
    let Some(tag_bytes) = from_hex(tag) else { return false; };
    if digest.len() != 24 || tag.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) { return false; }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, format!("alias:v1:{digest}").as_bytes(), &tag_bytes).is_ok()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 { return None; }
    value.as_bytes().chunks_exact(2).map(|pair| {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        Some(((hi << 4) | lo) as u8)
    }).collect()
}

fn filter_allowed(value: &Value, path: &str, allowed: &[String], removed: &mut Vec<String>) -> Option<Value> {
    if allowed.iter().any(|pattern| pointer_matches(pattern, path)) { return Some(value.clone()); }
    match value {
        Value::Object(object) => {
            let mut output = Map::new();
            for (key, child) in object {
                let child_path = format!("{path}/{}", escape_pointer(key));
                let directly_allowed = allowed.iter().any(|pattern| pointer_matches(pattern, &child_path));
                if directly_allowed || has_allowed_descendant(&child_path, allowed) {
                    if let Some(child) = filter_allowed(child, &child_path, allowed, removed) {
                        output.insert(key.clone(), child);
                    } else {
                        removed.push(child_path);
                    }
                } else {
                    removed.push(child_path);
                }
            }
            Some(Value::Object(output))
        }
        Value::Array(items) => {
            let mut output = Vec::new();
            for (index, child) in items.iter().enumerate() {
                let child_path = format!("{path}/{index}");
                let directly_allowed = allowed.iter().any(|pattern| pointer_matches(pattern, &child_path));
                if directly_allowed || has_allowed_descendant(&child_path, allowed) {
                    if let Some(child) = filter_allowed(child, &child_path, allowed, removed) {
                        output.push(child);
                    } else {
                        removed.push(child_path);
                    }
                } else {
                    removed.push(child_path);
                }
            }
            Some(Value::Array(output))
        }
        _ => {
            removed.push(path.to_string());
            None
        }
    }
}

fn pointer_matches(pattern: &str, path: &str) -> bool {
    let pattern = pointer_segments(pattern);
    let actual = pointer_segments(path);
    pattern.len() == actual.len()
        && pattern.iter().zip(actual).all(|(expected, found)| *expected == "*" || *expected == found)
}

fn has_allowed_descendant(path: &str, allowed: &[String]) -> bool {
    let actual = pointer_segments(path);
    allowed.iter().any(|pattern| {
        let pattern = pointer_segments(pattern);
        pattern.len() > actual.len()
            && pattern.iter().take(actual.len()).zip(&actual)
                .all(|(expected, found)| *expected == "*" || *expected == *found)
    })
}

fn pointer_segments(pointer: &str) -> Vec<&str> {
    pointer.strip_prefix('/').unwrap_or(pointer).split('/').collect()
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
