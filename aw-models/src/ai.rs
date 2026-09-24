use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;
use std::fmt;
use url::Url;
use crate::egress::EgressDecisionV1;

pub const AI_SCHEMA_VERSION_V1: u16 = 1;
pub const AI_MAX_ENDPOINT_PROFILES_V1: usize = 32;
pub const AI_MAX_AGGREGATE_BYTES_V1: usize = 64 * 1024;
pub const AI_MAX_QUESTION_BYTES_V1: usize = 4 * 1024;
pub const AI_MAX_RESULT_BYTES_V1: usize = 32 * 1024;
pub const AI_MAX_HISTORY_ENTRIES_V1: usize = 50;

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AIAccessModeV1 {
    Off,
    PeakAi,
    CustomEndpoint,
}

impl Default for AIAccessModeV1 {
    fn default() -> Self { Self::Off }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
pub enum AIEndpointProtocolV1 {
    #[serde(rename = "openai_chat_completions_v1")]
    OpenAiChatCompletionsV1,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AIAuthenticationV1 {
    None,
    Bearer,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AIDestinationTypeV1 {
    Remote,
    SelfHosted,
    Lan,
    PairedDevice,
    CentralSyncDevice,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AIRequestFeatureV1 {
    QuestionAnswer,
    ReportExplanation,
    CategorySuggestion,
    FreelancerDraft,
    PatternComparison,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AIEndpointProfileV1 {
    pub profile_id: String,
    pub display_name: String,
    pub origin: String,
    pub endpoint_path: String,
    pub protocol: AIEndpointProtocolV1,
    pub authentication: AIAuthenticationV1,
    pub model_id: String,
    pub destination_type: AIDestinationTypeV1,
    pub region_note: String,
    pub retention_note: String,
    pub training_note: String,
    pub cost_note: Option<String>,
    pub credential_ref: Option<String>,
    pub resolved_addresses: Vec<String>,
}

impl AIEndpointProfileV1 {
    pub fn validate(&self) -> Result<(), AIContractErrorV1> {
        if !valid_identifier(&self.profile_id)
            || !valid_short_text(&self.display_name, 80, true)
            || !valid_short_text(&self.model_id, 256, true)
            || !valid_short_text(&self.region_note, 256, true)
            || !valid_short_text(&self.retention_note, 512, true)
            || !valid_short_text(&self.training_note, 512, true)
            || self.cost_note.as_ref().is_some_and(|value| !valid_short_text(value, 512, false))
        {
            return Err(AIContractErrorV1::InvalidProfile);
        }
        let origin = Url::parse(&self.origin).map_err(|_| AIContractErrorV1::InvalidOrigin)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !matches!(origin.path(), "" | "/")
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(AIContractErrorV1::InvalidOrigin);
        }
        if !valid_endpoint_path(&self.endpoint_path) {
            return Err(AIContractErrorV1::InvalidEndpointPath);
        }
        if self.credential_ref.as_ref().is_some_and(|value| !valid_identifier(value)) {
            return Err(AIContractErrorV1::InvalidCredentialReference);
        }
        if (self.authentication == AIAuthenticationV1::None && self.credential_ref.is_some())
            || (self.authentication == AIAuthenticationV1::Bearer && self.credential_ref.is_none())
        {
            return Err(AIContractErrorV1::InvalidCredentialReference);
        }
        if self.resolved_addresses.len() > 16 {
            return Err(AIContractErrorV1::InvalidAddressPin);
        }
        let mut addresses = HashSet::new();
        for value in &self.resolved_addresses {
            let address = value.parse::<IpAddr>().map_err(|_| AIContractErrorV1::InvalidAddressPin)?;
            if !addresses.insert(address) {
                return Err(AIContractErrorV1::InvalidAddressPin);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AISettingsV1 {
    pub schema_version: u16,
    pub revision: u64,
    pub mode: AIAccessModeV1,
    pub active_connection_id: Option<String>,
    pub profiles: Vec<AIEndpointProfileV1>,
}

impl Default for AISettingsV1 {
    fn default() -> Self {
        Self {
            schema_version: AI_SCHEMA_VERSION_V1,
            revision: 0,
            mode: AIAccessModeV1::Off,
            active_connection_id: None,
            profiles: Vec::new(),
        }
    }
}

impl AISettingsV1 {
    pub fn validate(&self) -> Result<(), AIContractErrorV1> {
        if self.schema_version != AI_SCHEMA_VERSION_V1 || self.profiles.len() > AI_MAX_ENDPOINT_PROFILES_V1 {
            return Err(AIContractErrorV1::UnsupportedVersion);
        }
        let mut ids = HashSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            if !ids.insert(profile.profile_id.as_str()) {
                return Err(AIContractErrorV1::DuplicateProfile);
            }
        }
        if self.active_connection_id.as_ref().is_some_and(|id| !valid_identifier(id))
            || (self.mode != AIAccessModeV1::Off && self.active_connection_id.is_none())
        {
            return Err(AIContractErrorV1::InvalidActiveConnection);
        }
        if self.mode == AIAccessModeV1::CustomEndpoint
            && !self.active_connection_id.as_ref().is_some_and(|id| ids.contains(id.as_str()))
        {
            return Err(AIContractErrorV1::InvalidActiveConnection);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AIProviderV1 {
    pub provider_id: String,
    pub display_name: String,
    pub egress_destination_id: String,
    pub egress_purpose_id: String,
    pub model_id: String,
    pub model_version: String,
    pub region: String,
    pub retention_id: String,
    pub retention_disclosure: String,
    pub training_disclosure: String,
    pub subprocessors: Vec<String>,
    pub currency_code: String,
    pub input_price_micros_per_1k: u64,
    pub output_price_micros_per_1k: u64,
    pub monthly_cap_micros: u64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAIProviderRegistryV1 {
    pub schema_version: u16,
    pub version: u64,
    pub signer_key_id: String,
    pub providers: Vec<AIProviderV1>,
    pub signature: Vec<u8>,
}

impl SignedAIProviderRegistryV1 {
    pub fn validate(&self) -> Result<(), AIContractErrorV1> {
        if self.schema_version != AI_SCHEMA_VERSION_V1 || self.version == 0 {
            return Err(AIContractErrorV1::UnsupportedVersion);
        }
        if !valid_identifier(&self.signer_key_id)
            || self.providers.is_empty()
            || self.providers.len() > 64
            || self.signature.len() != 64
        {
            return Err(AIContractErrorV1::InvalidProviderRegistry);
        }
        let mut ids = HashSet::new();
        for provider in &self.providers {
            if !valid_identifier(&provider.provider_id)
                || !ids.insert(provider.provider_id.as_str())
                || !valid_short_text(&provider.display_name, 80, true)
                || !valid_identifier(&provider.egress_destination_id)
                || !valid_identifier(&provider.egress_purpose_id)
                || !valid_short_text(&provider.model_id, 256, true)
                || !valid_short_text(&provider.model_version, 128, true)
                || !valid_short_text(&provider.region, 128, true)
                || !valid_identifier(&provider.retention_id)
                || !valid_short_text(&provider.retention_disclosure, 1000, true)
                || !valid_short_text(&provider.training_disclosure, 1000, true)
                || provider.subprocessors.len() > 32
                || provider.subprocessors.iter().any(|value| !valid_short_text(value, 256, true))
                || provider.currency_code.len() != 3
                || !provider.currency_code.bytes().all(|byte| byte.is_ascii_uppercase())
                || provider.monthly_cap_micros == 0
            {
                return Err(AIContractErrorV1::InvalidProviderRegistry);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AIUserRequestV1 {
    pub schema_version: u16,
    pub profile_id: String,
    pub feature: AIRequestFeatureV1,
    pub question: String,
    pub aggregate: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Parse-only types reject fields outside the feature contract.
struct AIReportAggregateV1 {
    method_id: String,
    method_version: u32,
    break_time_seconds: u32,
    date_range: AIDateRangeV1,
    daily: Vec<AIDailySummaryV1>,
    coverage: AICoverageV1,
    weekly: Vec<AIWeeklySummaryV1>,
    monthly: Vec<AIMonthlySummaryV1>,
    #[serde(deserialize_with = "deserialize_required_option")]
    comparison: Option<AIComparisonV1>,
    prior_insight: Option<AIPriorInsightV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AIDateRangeV1 { start_date: String, end_date: String }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AIDailySummaryV1 {
    date: String,
    duration_seconds: f64,
    session_count: u32,
    average_session_seconds: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AICoverageV1 {
    requested_periods: u32,
    periods_with_data: u32,
    limitation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AIWeeklySummaryV1 {
    start_date: String,
    end_date: String,
    days_with_data: u32,
    duration_seconds: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AIMonthlySummaryV1 {
    period: String,
    days_with_data: u32,
    duration_seconds: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AIComparisonV1 {
    current: AIDateRangeV1,
    previous: AIDateRangeV1,
    duration_change_seconds: f64,
    #[serde(deserialize_with = "deserialize_required_option")]
    duration_change_percent: Option<f64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    coverage_note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AIPriorInsightV1 { profile_label: String, model_id: String, text: String }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AICategoryAggregateV1 {
    categories: Vec<String>,
    projects: Vec<AIProjectAliasV1>,
    existing_mappings: Vec<AICategoryMappingV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AIProjectAliasV1 { project_alias: String, display_label: Option<String> }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AICategoryMappingV1 { category: String, project_alias: String }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct AITimesheetAggregateV1 {
    project_alias: String,
    date: String,
    approved_duration_seconds: u32,
}

impl AIUserRequestV1 {
    pub fn validate(&self) -> Result<(), AIContractErrorV1> {
        if self.schema_version != AI_SCHEMA_VERSION_V1 {
            return Err(AIContractErrorV1::UnsupportedVersion);
        }
        if !valid_identifier(&self.profile_id)
            || !valid_question(&self.question)
            || self.aggregate.as_object().is_none()
        {
            return Err(AIContractErrorV1::InvalidRequest);
        }
        if disallowed_ai_purpose(&self.question) {
            return Err(AIContractErrorV1::DisallowedPurpose);
        }
        let payload = serde_json::to_vec(&self.aggregate).map_err(|_| AIContractErrorV1::InvalidRequest)?;
        if payload.len() > AI_MAX_AGGREGATE_BYTES_V1
            || !safe_aggregate(&self.aggregate, 0)
            || !valid_feature_aggregate(self.feature, &self.aggregate)
        {
            return Err(AIContractErrorV1::InvalidRequest);
        }
        Ok(())
    }
}

fn valid_feature_aggregate(feature: AIRequestFeatureV1, value: &Value) -> bool {
    match feature {
        AIRequestFeatureV1::QuestionAnswer | AIRequestFeatureV1::ReportExplanation | AIRequestFeatureV1::PatternComparison => {
            valid_report_aggregate(value)
        }
        AIRequestFeatureV1::CategorySuggestion => {
            serde_json::from_value::<AICategoryAggregateV1>(value.clone()).is_ok_and(|aggregate| {
                aggregate.projects.iter().all(|project| crate::freelancer::is_valid_project_alias(&project.project_alias))
                    && aggregate.existing_mappings.iter().all(|mapping| crate::freelancer::is_valid_project_alias(&mapping.project_alias))
            })
        }
        AIRequestFeatureV1::FreelancerDraft => {
            serde_json::from_value::<AITimesheetAggregateV1>(value.clone()).is_ok_and(|aggregate| {
                crate::ApprovedTimesheetV1 {
                    schema_version: 1,
                    project_alias: aggregate.project_alias,
                    date: aggregate.date,
                    approved_duration_seconds: aggregate.approved_duration_seconds,
                    user_note: None,
                }.validate().is_ok()
            })
        }
    }
}

fn valid_report_aggregate(value: &Value) -> bool {
    serde_json::from_value::<AIReportAggregateV1>(value.clone()).is_ok_and(|aggregate| {
        aggregate.daily.len() <= 62
            && aggregate.daily.iter().all(|day| day.duration_seconds >= 0.0 && day.average_session_seconds >= 0.0)
            && aggregate.weekly.iter().all(|week| week.duration_seconds >= 0.0)
            && aggregate.monthly.iter().all(|month| month.duration_seconds >= 0.0)
    })
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AIRequestPreviewV1 {
    pub profile_id: String,
    pub origin: String,
    pub model_id: String,
    pub purpose_id: String,
    pub retention_disclosure: String,
    pub decision: EgressDecisionV1,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AIResultV1 {
    pub schema_version: u16,
    pub source_mode: AIAccessModeV1,
    pub profile_label: String,
    pub model_id: String,
    pub text: String,
}

impl AIResultV1 {
    pub fn validate(&self) -> Result<(), AIContractErrorV1> {
        if self.schema_version != AI_SCHEMA_VERSION_V1
            || self.source_mode == AIAccessModeV1::Off
            || !valid_short_text(&self.profile_label, 80, true)
            || !valid_short_text(&self.model_id, 256, true)
            || self.text.len() > AI_MAX_RESULT_BYTES_V1
        {
            return Err(AIContractErrorV1::InvalidResult);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AIInsightV1 {
    pub insight_id: String,
    pub created_at: String,
    pub source_mode: AIAccessModeV1,
    pub profile_label: String,
    pub model_id: String,
    pub feature: AIRequestFeatureV1,
    pub text: String,
}

impl AIInsightV1 {
    pub fn validate(&self) -> Result<(), AIContractErrorV1> {
        if !valid_identifier(&self.insight_id)
            || self.source_mode == AIAccessModeV1::Off
            || !valid_short_text(&self.profile_label, 80, true)
            || !valid_short_text(&self.model_id, 256, true)
            || self.text.len() > AI_MAX_RESULT_BYTES_V1
            || chrono::DateTime::parse_from_rfc3339(&self.created_at).is_err()
        {
            return Err(AIContractErrorV1::InvalidResult);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AIInsightHistoryV1 {
    pub schema_version: u16,
    pub revision: u64,
    pub insights: Vec<AIInsightV1>,
}

impl Default for AIInsightHistoryV1 {
    fn default() -> Self {
        Self { schema_version: AI_SCHEMA_VERSION_V1, revision: 0, insights: Vec::new() }
    }
}

impl AIInsightHistoryV1 {
    pub fn validate(&self) -> Result<(), AIContractErrorV1> {
        if self.schema_version != AI_SCHEMA_VERSION_V1 || self.insights.len() > AI_MAX_HISTORY_ENTRIES_V1 {
            return Err(AIContractErrorV1::UnsupportedVersion);
        }
        let mut ids = HashSet::new();
        for insight in &self.insights {
            insight.validate()?;
            if !ids.insert(insight.insight_id.as_str()) {
                return Err(AIContractErrorV1::InvalidResult);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AIContractErrorV1 {
    UnsupportedVersion,
    InvalidProfile,
    InvalidOrigin,
    InvalidEndpointPath,
    InvalidCredentialReference,
    InvalidAddressPin,
    DuplicateProfile,
    InvalidActiveConnection,
    InvalidProviderRegistry,
    InvalidRequest,
    DisallowedPurpose,
    InvalidResult,
}

impl fmt::Display for AIContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "Unsupported AI contract version",
            Self::InvalidProfile => "Invalid AI endpoint profile",
            Self::InvalidOrigin => "AI endpoint origin must be an exact HTTPS origin",
            Self::InvalidEndpointPath => "Invalid AI endpoint path",
            Self::InvalidCredentialReference => "Invalid AI credential reference",
            Self::InvalidAddressPin => "Invalid AI endpoint address pin",
            Self::DuplicateProfile => "Duplicate AI endpoint profile",
            Self::InvalidActiveConnection => "Invalid active AI connection",
            Self::InvalidProviderRegistry => "Invalid signed AI provider registry",
            Self::InvalidRequest => "Invalid or unsafe AI request",
            Self::DisallowedPurpose => "AI cannot make mental-health, emotion, personality or worker-scoring judgments",
            Self::InvalidResult => "Invalid AI result",
        })
    }
}

impl std::error::Error for AIContractErrorV1 {}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')))
        })
}

fn valid_short_text(value: &str, max_bytes: usize, required: bool) -> bool {
    (!required || !value.trim().is_empty())
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_question(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= AI_MAX_QUESTION_BYTES_V1
        && !value.chars().any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn valid_endpoint_path(value: &str) -> bool {
    if value == "/" { return true; }
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 256
        && !value.chars().any(|character| matches!(character, '?' | '#' | '\\' | '%'))
        && !value.chars().any(char::is_control)
        && value.split('/').skip(1).all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn safe_aggregate(value: &Value, depth: usize) -> bool {
    if depth > 10 { return false; }
    match value {
        Value::Object(object) => object.len() <= 128 && object.iter().all(|(key, value)| {
            if key.chars().any(char::is_control) { return false; }
            let normalized: String = key.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect();
            let forbidden = [
                "event", "events", "eventid", "eventids", "bucketid", "bucketids",
                "windowtitle", "url", "urls", "path", "paths", "filepath", "fullpath",
                "rawactivity", "rawdata", "userid", "deviceid", "hostname", "clientid",
                "apikey", "credential", "authorization", "token", "password", "secret", "privatekey",
            ];
            !forbidden.iter().any(|needle| normalized.contains(needle)) && safe_aggregate(value, depth + 1)
        }),
        Value::Array(items) => items.len() <= 256 && items.iter().all(|item| safe_aggregate(item, depth + 1)),
        Value::String(text) => text.len() <= 4096
            && !text.chars().any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t')),
        _ => true,
    }
}

fn disallowed_ai_purpose(question: &str) -> bool {
    // ponytail: v1 blocks common explicit wording only; keep release AI unavailable until safety evaluation covers paraphrases and multilingual inputs.
    let words = question.to_ascii_lowercase().chars()
        .map(|character| if character.is_ascii_alphanumeric() { character } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let normalized = format!(" {} ", words.join(" "));
    let worker_scoring = words.iter().any(|word| matches!(word.as_str(), "score" | "scoring" | "rank" | "ranking" | "rate" | "rating" | "evaluate" | "assess"))
        && words.iter().any(|word| matches!(word.as_str(), "employee" | "employees" | "worker" | "workers" | "staff"));
    worker_scoring || [
        "mental health", "burnout", "depression", "anxiety", "mood", "emotion", "personality",
        "wellbeing", "well being", "employee value", "worker value", "productivity score", "performance score",
        "employee ranking", "worker ranking",
    ].iter().any(|phrase| normalized.contains(&format!(" {phrase} ")))
}
