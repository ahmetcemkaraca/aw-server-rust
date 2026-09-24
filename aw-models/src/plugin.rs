use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::{AIRequestFeatureV1, AIUserRequestV1, SYNC_EGRESS_PURPOSE_V1};
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use serde_json::Value;

pub const PLUGIN_SCHEMA_VERSION_V1: u16 = 1;
pub const PLUGIN_MAX_GRANTS_V1: usize = 32;
// ponytail: cap V1 storage at half the invocation input limit; add keyed/paged reads if plugins need larger caches.
pub const PLUGIN_MAX_STORAGE_BYTES_V1: u64 = 512 * 1024;
// ponytail: cap plugin-owned annotation events at 512 KiB per publisher/plugin; add explicit retention or export before raising it.
pub const PLUGIN_MAX_PLUGIN_EVENT_BYTES_V1: u64 = 512 * 1024;
pub const PLUGIN_MIN_BACKGROUND_INTERVAL_SECONDS_V1: u32 = 15 * 60;
pub const PLUGIN_MAX_BACKGROUND_RUNTIME_MS_V1: u32 = 30_000;
pub const PLUGIN_MAX_BACKGROUND_MEMORY_BYTES_V1: u32 = 128 * 1024 * 1024;
pub const PLUGIN_MAX_INVOCATION_OUTPUT_BYTES_V1: usize = 1024 * 1024;
pub const PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1: usize = 64 * 1024;
pub const PLUGIN_MAX_INVOCATION_RECORDS_V1: usize = 512;
pub const PLUGIN_MAX_INVOCATION_INPUT_BYTES_V1: usize = 1024 * 1024;
pub const PLUGIN_AGGREGATE_FIELDS_V1: [&str; 2] = ["/event_count", "/total_duration_seconds"];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginDataClassV1 { Raw, Aggregate }

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginPayloadClassV1 { Aggregate, ApprovedTimesheet, PluginMetadata }

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginUISurfaceV1 { SettingsPanel, WorkReport, ToolbarAction }

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginDestructiveActionV1 { Export, Delete, Send }

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginReadCapabilityV1 {
    pub data_class: PluginDataClassV1,
    pub bucket_type: String,
    pub event_type: String,
    pub time_window_days: u16,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginWriteCapabilityV1 {
    pub event_type: String,
    pub schema_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginNetworkCapabilityV1 {
    pub domain: String,
    pub destination_id: String,
    pub purpose_id: String,
    pub payload_class: PluginPayloadClassV1,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginStorageCapabilityV1 {
    pub quota_bytes: u64,
    pub encrypted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginBackgroundCapabilityV1 {
    pub minimum_interval_seconds: u32,
    pub maximum_runtime_ms: u32,
    pub maximum_memory_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginDestructiveCapabilityV1 {
    pub action: PluginDestructiveActionV1,
    pub confirmation_required: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilitiesV1 {
    pub read: Vec<PluginReadCapabilityV1>,
    pub write: Vec<PluginWriteCapabilityV1>,
    pub network: Vec<PluginNetworkCapabilityV1>,
    pub ai_features: Vec<AIRequestFeatureV1>,
    pub storage: Option<PluginStorageCapabilityV1>,
    pub ui: Vec<PluginUISurfaceV1>,
    pub background: Option<PluginBackgroundCapabilityV1>,
    pub destructive: Vec<PluginDestructiveCapabilityV1>,
}

impl PluginCapabilitiesV1 {
    pub fn validate(&self) -> Result<(), PluginContractErrorV1> {
        if [self.read.len(), self.write.len(), self.network.len(), self.ai_features.len(), self.ui.len(), self.destructive.len()]
            .into_iter().any(|count| count > PLUGIN_MAX_GRANTS_V1)
            || duplicate(&self.ui)
            || self.ai_features.iter().enumerate().any(|(index, feature)| self.ai_features[index + 1..].contains(feature))
            || self.read.iter().any(|grant| {
                !valid_identifier(&grant.bucket_type) || !valid_identifier(&grant.event_type)
                    || !(1..=365).contains(&grant.time_window_days)
                    || grant.fields.is_empty() || grant.fields.len() > 64
                    || grant.fields.iter().any(|field| !valid_exact_field(field))
                    || (grant.data_class == PluginDataClassV1::Aggregate && grant.fields.iter()
                        .any(|field| !PLUGIN_AGGREGATE_FIELDS_V1.contains(&field.as_str())))
                    || duplicate(&grant.fields)
            })
            || self.write.iter().any(|grant| !valid_identifier(&grant.event_type) || !valid_identifier(&grant.schema_id))
            || self.network.iter().any(|grant| {
                !valid_domain(&grant.domain) || !valid_identifier(&grant.destination_id)
                    || !valid_identifier(&grant.purpose_id)
                    || grant.purpose_id == SYNC_EGRESS_PURPOSE_V1
                    || grant.purpose_id.starts_with("ai.")
            })
            || self.storage.as_ref().is_some_and(|storage| {
                storage.quota_bytes == 0 || storage.quota_bytes > PLUGIN_MAX_STORAGE_BYTES_V1 || !storage.encrypted
            })
            || self.background.as_ref().is_some_and(|background| {
                background.minimum_interval_seconds < PLUGIN_MIN_BACKGROUND_INTERVAL_SECONDS_V1
                    || background.maximum_runtime_ms == 0
                    || background.maximum_runtime_ms > PLUGIN_MAX_BACKGROUND_RUNTIME_MS_V1
                    || background.maximum_memory_bytes == 0
                    || background.maximum_memory_bytes > PLUGIN_MAX_BACKGROUND_MEMORY_BYTES_V1
            })
            || self.destructive.iter().any(|grant| !grant.confirmation_required)
            || duplicate(&self.destructive.iter().map(|grant| grant.action).collect::<Vec<_>>())
        {
            return Err(PluginContractErrorV1::InvalidCapabilities);
        }
        Ok(())
    }

    fn tokens(&self) -> BTreeSet<String> {
        let mut tokens = BTreeSet::new();
        for grant in &self.read {
            for field in &grant.fields {
                tokens.insert(format!("read/{:?}/{}/{}/{}/{}", grant.data_class, grant.bucket_type, grant.event_type, grant.time_window_days, field));
            }
        }
        tokens.extend(self.write.iter().map(|grant| format!("write/{}/{}", grant.event_type, grant.schema_id)));
        tokens.extend(self.network.iter().map(|grant| format!("network/{}/{}/{}/{:?}", grant.domain, grant.destination_id, grant.purpose_id, grant.payload_class)));
        tokens.extend(self.ai_features.iter().map(|feature| format!("ai/{feature:?}")));
        tokens.extend(self.ui.iter().map(|surface| format!("ui/{surface:?}")));
        tokens.extend(self.destructive.iter().map(|grant| format!("destructive/{:?}/confirmation", grant.action)));
        if let Some(storage) = &self.storage {
            tokens.insert(format!("storage/encrypted/quota={}", storage.quota_bytes));
        }
        if let Some(background) = &self.background {
            tokens.insert(format!("background/{}/{}/{}", background.minimum_interval_seconds, background.maximum_runtime_ms, background.maximum_memory_bytes));
        }
        tokens
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifestV1 {
    pub schema_version: u16,
    pub plugin_id: String,
    pub version: String,
    pub publisher_key_id: String,
    pub display_name: String,
    pub description: String,
    pub capabilities: PluginCapabilitiesV1,
}

impl PluginManifestV1 {
    pub fn validate(&self) -> Result<(), PluginContractErrorV1> {
        if self.schema_version != PLUGIN_SCHEMA_VERSION_V1
            || !valid_identifier(&self.plugin_id)
            || !valid_identifier(&self.publisher_key_id)
            || !valid_semver(&self.version)
            || !valid_text(&self.display_name, 80, true)
            || !valid_text(&self.description, 1000, false)
        {
            return Err(PluginContractErrorV1::InvalidManifest);
        }
        self.capabilities.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPluginPackageV1 {
    pub schema_version: u16,
    pub manifest: PluginManifestV1,
    /// Lowercase hexadecimal SHA-256 of the separately delivered module bytes.
    pub module_sha256: String,
    pub signature: Vec<u8>,
}

impl SignedPluginPackageV1 {
    pub fn validate(&self) -> Result<(), PluginContractErrorV1> {
        if self.schema_version != PLUGIN_SCHEMA_VERSION_V1
            || !self.module_sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.module_sha256.len() != 64
            || self.signature.len() != 64
        {
            return Err(PluginContractErrorV1::InvalidPackage);
        }
        self.manifest.validate().map_err(|_| PluginContractErrorV1::InvalidPackage)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilityDiffV1 {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub requires_reconsent: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginInputRecordV1 {
    pub data_class: PluginDataClassV1,
    pub bucket_type: String,
    pub event_type: String,
    /// Used by the host for time-window enforcement and omitted from validated plugin input.
    pub captured_at: String,
    /// Included for aggregate records so distinct granted windows remain distinguishable.
    #[serde(default)]
    pub time_window_days: Option<u16>,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginInvocationInputV1 {
    pub schema_version: u16,
    pub records: Vec<PluginInputRecordV1>,
    #[serde(default)]
    pub storage: BTreeMap<String, Value>,
}

/// A validated input token contains only manifest-allowed fields, with timestamps removed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPluginInputV1 {
    plugin_id: String,
    version: String,
    publisher_key_id: String,
    capabilities: PluginCapabilitiesV1,
    serialized: Vec<u8>,
}

impl ValidatedPluginInputV1 {
    pub fn serialized(&self) -> &[u8] { &self.serialized }
    pub fn is_for_manifest(&self, manifest: &PluginManifestV1) -> bool {
        self.plugin_id == manifest.plugin_id
            && self.version == manifest.version
            && self.publisher_key_id == manifest.publisher_key_id
            && self.capabilities == manifest.capabilities
    }
}

pub fn validate_plugin_input_v1(
    manifest: &PluginManifestV1,
    input: PluginInvocationInputV1,
    now: DateTime<Utc>,
) -> Result<ValidatedPluginInputV1, PluginContractErrorV1> {
    manifest.validate()?;
    if input.schema_version != PLUGIN_SCHEMA_VERSION_V1
        || input.records.len() > PLUGIN_MAX_INVOCATION_RECORDS_V1
        || serde_json::to_vec(&input).map_err(|_| PluginContractErrorV1::InvalidInput)?.len() > PLUGIN_MAX_INVOCATION_INPUT_BYTES_V1
    {
        return Err(PluginContractErrorV1::InvalidInput);
    }
    let storage_limit = manifest.capabilities.storage.as_ref().map_or(0, |storage| storage.quota_bytes);
    let storage_bytes = input.storage.iter().try_fold(0_u64, |total, (key, value)| {
        let value_bytes = u64::try_from(serde_json::to_vec(value).ok()?.len()).ok()?;
        total.checked_add(key.len() as u64)?.checked_add(value_bytes)
    });
    if input.storage.iter().any(|(key, value)| {
        !valid_plugin_storage_key(key)
            || serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1)
    }) || storage_bytes.is_none_or(|bytes| bytes > storage_limit) {
        return Err(PluginContractErrorV1::CapabilityDenied);
    }
    let storage = input.storage;
    let mut visible_records = Vec::new();
    for record in input.records {
        if !valid_identifier(&record.bucket_type) || !valid_identifier(&record.event_type) || !record.payload.is_object()
            || (record.data_class == PluginDataClassV1::Aggregate) != record.time_window_days.is_some()
            || record.time_window_days.is_some_and(|days| !(1..=365).contains(&days))
        {
            return Err(PluginContractErrorV1::InvalidInput);
        }
        let captured_at = DateTime::parse_from_rfc3339(&record.captured_at)
            .map_err(|_| PluginContractErrorV1::InvalidInput)?.with_timezone(&Utc);
        let age = now.signed_duration_since(captured_at).num_seconds();
        if age < -300 { return Err(PluginContractErrorV1::InvalidInput); }
        let fields = manifest.capabilities.read.iter()
            .filter(|grant| grant.data_class == record.data_class && grant.bucket_type == record.bucket_type
                && grant.event_type == record.event_type
                && record.time_window_days.is_none_or(|days| grant.time_window_days == days)
                && age <= i64::from(grant.time_window_days) * 86_400)
            .flat_map(|grant| grant.fields.iter().map(|field| normalize_field_pointer(field)))
            .collect::<BTreeSet<_>>();
        if fields.is_empty() { continue; }
        let Some(payload) = filter_exact_fields(&record.payload, "", &fields) else { continue; };
        let mut visible_record = serde_json::json!({
            "data_class": record.data_class,
            "bucket_type": record.bucket_type,
            "event_type": record.event_type,
            "payload": payload,
        });
        if let Some(window) = record.time_window_days {
            visible_record["time_window_days"] = serde_json::json!(window);
        }
        visible_records.push(visible_record);
    }
    let serialized = serde_json::to_vec(&serde_json::json!({
        "schema_version": PLUGIN_SCHEMA_VERSION_V1,
        "records": visible_records,
        "storage": storage,
    })).map_err(|_| PluginContractErrorV1::InvalidInput)?;
    if serialized.len() > PLUGIN_MAX_INVOCATION_INPUT_BYTES_V1 {
        return Err(PluginContractErrorV1::InvalidInput);
    }
    Ok(ValidatedPluginInputV1 {
        plugin_id: manifest.plugin_id.clone(),
        version: manifest.version.clone(),
        publisher_key_id: manifest.publisher_key_id.clone(),
        capabilities: manifest.capabilities.clone(),
        serialized,
    })
}

fn normalize_field_pointer(field: &str) -> String {
    if field.starts_with('/') { field.to_owned() }
    else { format!("/{}", field.replace('~', "~0").replace('/', "~1")) }
}

fn filter_exact_fields(value: &Value, path: &str, allowed: &BTreeSet<String>) -> Option<Value> {
    if allowed.contains(path) { return Some(value.clone()); }
    match value {
        Value::Object(object) => {
            let mut filtered = serde_json::Map::new();
            for (key, child) in object {
                let child_path = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                if let Some(child) = filter_exact_fields(child, &child_path, allowed) {
                    filtered.insert(key.clone(), child);
                }
            }
            (!filtered.is_empty()).then_some(Value::Object(filtered))
        }
        Value::Array(items) => {
            let filtered = items.iter().enumerate().filter_map(|(index, child)| {
                filter_exact_fields(child, &format!("{path}/{index}"), allowed)
            }).collect::<Vec<_>>();
            (!filtered.is_empty()).then_some(Value::Array(filtered))
        }
        _ => None,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginUIOutputV1 {
    pub surface: PluginUISurfaceV1,
    pub title: String,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginWriteIntentV1 {
    pub event_type: String,
    pub schema_id: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginOwnedEventV1 {
    pub schema_version: u16,
    pub publisher_key_id: String,
    pub plugin_id: String,
    pub event_id: u64,
    pub event_type: String,
    pub schema_id: String,
    pub created_at: DateTime<Utc>,
    pub payload: Value,
}

pub fn validate_plugin_write_intent_v1(intent: &PluginWriteIntentV1) -> Result<(), PluginContractErrorV1> {
    if intent.event_type != "plugin.annotation" || intent.schema_id != "annotation-v1"
        || serde_json::to_vec(&intent.payload).map_or(true, |bytes| bytes.len() > PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1)
    {
        return Err(PluginContractErrorV1::InvalidOutput);
    }
    let Some(payload) = intent.payload.as_object() else { return Err(PluginContractErrorV1::InvalidOutput); };
    if payload.len() != 2
        || !payload.get("title").and_then(Value::as_str).is_some_and(|value| valid_text(value, 80, true))
        || !payload.get("body").and_then(Value::as_str).is_some_and(|value| valid_text(value, 4096, true))
    {
        return Err(PluginContractErrorV1::InvalidOutput);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginNetworkIntentV1 {
    pub domain: String,
    pub destination_id: String,
    pub purpose_id: String,
    pub payload_class: PluginPayloadClassV1,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginAIIntentV1 {
    pub feature: AIRequestFeatureV1,
    pub question: String,
    pub aggregate: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginStorageIntentV1 {
    pub key: String,
    pub value: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginDestructiveIntentV1 {
    pub action: PluginDestructiveActionV1,
    pub resource_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginInvocationOutputV1 {
    pub schema_version: u16,
    pub ui: Vec<PluginUIOutputV1>,
    pub writes: Vec<PluginWriteIntentV1>,
    pub network: Vec<PluginNetworkIntentV1>,
    pub ai: Vec<PluginAIIntentV1>,
    pub storage: Vec<PluginStorageIntentV1>,
    pub destructive: Vec<PluginDestructiveIntentV1>,
}

/// A host can only receive intents that passed the installed manifest checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPluginOutputV1 {
    plugin_id: String,
    version: String,
    publisher_key_id: String,
    capabilities: PluginCapabilitiesV1,
    output: PluginInvocationOutputV1,
}

impl ValidatedPluginOutputV1 {
    pub fn as_inner(&self) -> &PluginInvocationOutputV1 { &self.output }
    pub fn into_inner(self) -> PluginInvocationOutputV1 { self.output }
    pub fn is_for_manifest(&self, manifest: &PluginManifestV1) -> bool {
        self.plugin_id == manifest.plugin_id
            && self.version == manifest.version
            && self.publisher_key_id == manifest.publisher_key_id
            && self.capabilities == manifest.capabilities
    }
}

pub fn validate_plugin_output_v1(
    manifest: &PluginManifestV1,
    output: PluginInvocationOutputV1,
    active_ai_profile_id: Option<&str>,
) -> Result<ValidatedPluginOutputV1, PluginContractErrorV1> {
    manifest.validate()?;
    if output.schema_version != PLUGIN_SCHEMA_VERSION_V1
        || [output.ui.len(), output.writes.len(), output.network.len(), output.ai.len(), output.storage.len(), output.destructive.len()]
            .into_iter().any(|count| count > PLUGIN_MAX_GRANTS_V1)
        || serde_json::to_vec(&output).map_err(|_| PluginContractErrorV1::InvalidOutput)?.len() > PLUGIN_MAX_INVOCATION_OUTPUT_BYTES_V1
    {
        return Err(PluginContractErrorV1::InvalidOutput);
    }
    let allowed_network = &manifest.capabilities.network;
    if output.ui.iter().any(|intent| {
        !manifest.capabilities.ui.contains(&intent.surface)
            || !valid_text(&intent.title, 80, true)
            || !valid_text(&intent.text, 16 * 1024, false)
    }) || output.writes.iter().any(|intent| {
        !manifest.capabilities.write.iter().any(|grant| grant.event_type == intent.event_type && grant.schema_id == intent.schema_id)
            || validate_plugin_write_intent_v1(intent).is_err()
    }) || output.network.iter().any(|intent| {
        !allowed_network.iter().any(|grant| grant.domain == intent.domain
            && grant.destination_id == intent.destination_id
            && grant.purpose_id == intent.purpose_id
            && grant.payload_class == intent.payload_class)
            || !intent.payload.is_object()
            || serde_json::to_vec(&intent.payload).map_or(true, |bytes| bytes.len() > PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1)
    }) || output.ai.iter().any(|intent| !ai_intent_allowed(manifest, intent, active_ai_profile_id))
        || output.storage.iter().any(|intent| {
        !manifest.capabilities.storage.as_ref().is_some_and(|storage| storage.encrypted && storage.quota_bytes > 0)
            || !valid_plugin_storage_key(&intent.key)
            || intent.value.as_ref().is_some_and(|value| serde_json::to_vec(value)
                .map_or(true, |bytes| bytes.len() > PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1))
    }) || output.destructive.iter().any(|intent| {
        !manifest.capabilities.destructive.iter().any(|grant| grant.action == intent.action && grant.confirmation_required)
            || !valid_text(&intent.resource_id, 128, true)
        }) {
        return Err(PluginContractErrorV1::CapabilityDenied);
    }
    Ok(ValidatedPluginOutputV1 {
        plugin_id: manifest.plugin_id.clone(),
        version: manifest.version.clone(),
        publisher_key_id: manifest.publisher_key_id.clone(),
        capabilities: manifest.capabilities.clone(),
        output,
    })
}

fn valid_plugin_storage_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 128 && !key.chars().any(char::is_control)
}

fn ai_intent_allowed(
    manifest: &PluginManifestV1,
    intent: &PluginAIIntentV1,
    active_ai_profile_id: Option<&str>,
) -> bool {
    let Some(profile_id) = active_ai_profile_id.filter(|id| valid_identifier(id)) else { return false; };
    manifest.capabilities.ai_features.contains(&intent.feature)
        && AIUserRequestV1 {
            schema_version: 1,
            profile_id: profile_id.to_owned(),
            feature: intent.feature,
            question: intent.question.clone(),
            aggregate: intent.aggregate.clone(),
        }.validate().is_ok()
}

pub fn plugin_capability_diff_v1(
    previous: &PluginCapabilitiesV1,
    next: &PluginCapabilitiesV1,
) -> Result<PluginCapabilityDiffV1, PluginContractErrorV1> {
    previous.validate()?;
    next.validate()?;
    let previous = previous.tokens();
    let next = next.tokens();
    let added = next.difference(&previous).cloned().collect::<Vec<_>>();
    let removed = previous.difference(&next).cloned().collect::<Vec<_>>();
    Ok(PluginCapabilityDiffV1 { requires_reconsent: !added.is_empty(), added, removed })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginContractErrorV1 { InvalidManifest, InvalidCapabilities, InvalidPackage, InvalidInput, InvalidOutput, CapabilityDenied }

impl fmt::Display for PluginContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidManifest => "Invalid plugin manifest",
            Self::InvalidCapabilities => "Invalid plugin capability grant",
            Self::InvalidPackage => "Invalid signed plugin package",
            Self::InvalidInput => "Invalid or out-of-scope plugin input",
            Self::InvalidOutput => "Invalid plugin invocation output",
            Self::CapabilityDenied => "Plugin output exceeds its granted capabilities",
        })
    }
}

impl std::error::Error for PluginContractErrorV1 {}

fn duplicate<T: Ord>(items: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    items.iter().any(|item| !seen.insert(item))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')))
    })
}

fn valid_semver(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3 && parts.iter().all(|part| {
        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part.len() == 1 || !part.starts_with('0')) && part.parse::<u32>().is_ok()
    })
}

fn valid_text(value: &str, limit: usize, required: bool) -> bool {
    (!required || !value.trim().is_empty()) && value.len() <= limit && !value.chars().any(char::is_control)
}

fn valid_exact_field(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || value.contains('*') || value.chars().any(char::is_control) {
        return false;
    }
    let Some(pointer) = value.strip_prefix('/') else { return valid_identifier(value); };
    !pointer.is_empty() && pointer.split('/').all(|segment| {
        if segment.is_empty() { return false; }
        let mut chars = segment.chars();
        while let Some(character) = chars.next() {
            if character == '~' && !matches!(chars.next(), Some('0' | '1')) { return false; }
        }
        true
    })
}

fn valid_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.contains('*') || value.ends_with('.') || value.to_ascii_lowercase() != value {
        return false;
    }
    let labels = value.split('.').collect::<Vec<_>>();
    labels.len() >= 2 && labels.iter().all(|label| {
        !label.is_empty() && label.len() <= 63
            && (label.as_bytes()[0].is_ascii_lowercase() || label.as_bytes()[0].is_ascii_digit())
            && (label.as_bytes()[label.len() - 1].is_ascii_lowercase() || label.as_bytes()[label.len() - 1].is_ascii_digit())
            && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}
