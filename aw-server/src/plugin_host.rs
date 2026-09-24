//! Host-side plugin data preparation and storage application.
//!
//! This module is not mounted as a runtime route. Returned network, AI, write
//! and destructive intents still require their existing preview/approval path.
use aw_datastore::{Datastore, DatastoreError};
use aw_models::{
    validate_plugin_input_v1, AIUserRequestV1, EgressDecisionV1, EgressRequestV1,
    PluginDataClassV1, PluginDestructiveIntentV1, PluginInputRecordV1,
    PluginInvocationInputV1, PluginInvocationOutputV1, PluginManifestV1,
    PluginNetworkIntentV1, PluginUIOutputV1, PluginWriteIntentV1, PluginContractErrorV1,
    ValidatedPluginInputV1, ValidatedPluginOutputV1, PLUGIN_SCHEMA_VERSION_V1,
    PLUGIN_MAX_INVOCATION_RECORDS_V1,
};
use aw_egress::{validate_plugin_egress_grants_v1, EgressProxy, VerifiedPolicyV1};
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginHostErrorV1 {
    VaultUnavailable,
    InvalidManifest,
    InvalidInput,
    InvalidOutput,
    StorageUnavailable,
    EgressPolicyUnavailable,
}

#[derive(Clone, Debug)]
pub struct PreparedPluginActionsV1 {
    pub ui: Vec<PluginUIOutputV1>,
    pub writes: Vec<PluginWriteIntentV1>,
    pub network_previews: Vec<EgressDecisionV1>,
    pub ai_requests: Vec<AIUserRequestV1>,
    pub destructive_confirmations: Vec<PluginDestructiveIntentV1>,
}

pub fn prepare_plugin_input(
    datastore: &Datastore,
    manifest: &PluginManifestV1,
    now: DateTime<Utc>,
) -> Result<ValidatedPluginInputV1, PluginHostErrorV1> {
    if !datastore.is_encrypted() { return Err(PluginHostErrorV1::VaultUnavailable); }
    manifest.validate().map_err(|_| PluginHostErrorV1::InvalidManifest)?;
    let buckets = datastore.get_buckets().map_err(|_| PluginHostErrorV1::StorageUnavailable)?;
    let mut records = Vec::new();
    for bucket in buckets.values() {
        let grants = manifest.capabilities.read.iter()
            .filter(|grant| grant.data_class == PluginDataClassV1::Raw && grant.bucket_type == bucket._type)
            .collect::<Vec<_>>();
        let aggregate_grants = manifest.capabilities.read.iter()
            .filter(|grant| grant.data_class == PluginDataClassV1::Aggregate && grant.bucket_type == bucket._type)
            .collect::<Vec<_>>();
        let Some(days) = grants.iter().chain(&aggregate_grants).map(|grant| grant.time_window_days).max() else { continue; };
        let start = now - Duration::days(i64::from(days));
        let events = datastore.get_events(
            &bucket.id,
            Some(start),
            Some(now + Duration::seconds(5)),
            Some((PLUGIN_MAX_INVOCATION_RECORDS_V1 + 1) as u64),
        ).map_err(|_| PluginHostErrorV1::StorageUnavailable)?;
        if events.len() > PLUGIN_MAX_INVOCATION_RECORDS_V1 {
            return Err(PluginHostErrorV1::InvalidInput);
        }
        let mut aggregate_totals = aggregate_grants.iter().map(|grant| (*grant, 0_u64, 0_i64)).collect::<Vec<_>>();
        for event in events {
            let event_type = event.data.get("event_type").and_then(serde_json::Value::as_str)
                .unwrap_or("activity");
            let age = now.signed_duration_since(event.timestamp).num_seconds();
            if age < -300 { return Err(PluginHostErrorV1::InvalidInput); }
            let duration_seconds = event.duration.num_seconds();
            if duration_seconds < 0 { return Err(PluginHostErrorV1::InvalidInput); }
            if grants.iter().any(|grant| grant.event_type == event_type
                && age <= i64::from(grant.time_window_days) * 86_400)
            {
                records.push(PluginInputRecordV1 {
                    data_class: PluginDataClassV1::Raw,
                    bucket_type: bucket._type.clone(),
                    event_type: event_type.into(),
                    captured_at: event.timestamp.to_rfc3339(),
                    time_window_days: None,
                    payload: serde_json::Value::Object(event.data.clone()),
                });
            }
            for (grant, count, duration) in &mut aggregate_totals {
                if grant.event_type == event_type && age <= i64::from(grant.time_window_days) * 86_400 {
                    *count = count.checked_add(1).ok_or(PluginHostErrorV1::InvalidInput)?;
                    *duration = duration.checked_add(duration_seconds).ok_or(PluginHostErrorV1::InvalidInput)?;
                }
            }
            if records.len() > PLUGIN_MAX_INVOCATION_RECORDS_V1 {
                return Err(PluginHostErrorV1::InvalidInput);
            }
        }
        for (grant, count, duration) in aggregate_totals.into_iter().filter(|(_, count, _)| *count > 0) {
            let mut payload = serde_json::Map::new();
            if grant.fields.iter().any(|field| field == "/event_count") {
                payload.insert("event_count".into(), serde_json::json!(count));
            }
            if grant.fields.iter().any(|field| field == "/total_duration_seconds") {
                payload.insert("total_duration_seconds".into(), serde_json::json!(duration));
            }
            records.push(PluginInputRecordV1 {
                data_class: PluginDataClassV1::Aggregate,
                bucket_type: bucket._type.clone(),
                event_type: grant.event_type.clone(),
                captured_at: now.to_rfc3339(),
                time_window_days: Some(grant.time_window_days),
                payload: serde_json::Value::Object(payload),
            });
            if records.len() > PLUGIN_MAX_INVOCATION_RECORDS_V1 {
                return Err(PluginHostErrorV1::InvalidInput);
            }
        }
    }
    let storage = if manifest.capabilities.storage.is_some() {
        datastore.get_plugin_storage(manifest).map_err(map_storage_error)?
    } else {
        BTreeMap::new()
    };
    validate_plugin_input_v1(manifest, PluginInvocationInputV1 {
        schema_version: PLUGIN_SCHEMA_VERSION_V1,
        records,
        storage,
    }, now).map_err(map_input_error)
}

/// Persist only this plugin's granted storage. Other effects stay prepared until
/// their approval flow runs; this helper never stores plugin-owned events.
pub fn apply_plugin_output(
    datastore: &Datastore,
    manifest: &PluginManifestV1,
    output: ValidatedPluginOutputV1,
) -> Result<PluginInvocationOutputV1, PluginHostErrorV1> {
    if !datastore.is_encrypted() { return Err(PluginHostErrorV1::VaultUnavailable); }
    if !output.is_for_manifest(manifest) { return Err(PluginHostErrorV1::InvalidOutput); }
    datastore.apply_plugin_storage_intents(manifest, &output.as_inner().storage).map_err(map_storage_error)?;
    Ok(output.into_inner())
}

/// Store permitted plugin-owned data and prepare all other effects for existing approval flows.
/// This function never sends network requests or performs writes/destructive actions.
pub fn prepare_plugin_actions(
    datastore: &Datastore,
    proxy: &EgressProxy,
    policy: &VerifiedPolicyV1,
    manifest: &PluginManifestV1,
    output: ValidatedPluginOutputV1,
    active_ai_profile_id: Option<&str>,
    now: DateTime<Utc>,
    local_offset_seconds: i32,
) -> Result<PreparedPluginActionsV1, PluginHostErrorV1> {
    if !output.is_for_manifest(manifest) { return Err(PluginHostErrorV1::InvalidOutput); }
    validate_plugin_egress_grants_v1(manifest, policy)
        .map_err(|_| PluginHostErrorV1::EgressPolicyUnavailable)?;
    let inner = output.as_inner();
    let purposes = &policy.policy().purposes;
    let mut network_previews = Vec::with_capacity(inner.network.len());
    for intent in &inner.network {
        network_previews.push(preview_network_intent(
            proxy, policy, purposes, intent, now, local_offset_seconds,
        )?);
    }
    let ai_requests = inner.ai.iter().map(|intent| {
        let profile_id = active_ai_profile_id.filter(|value| !value.trim().is_empty())
            .ok_or(PluginHostErrorV1::InvalidOutput)?;
        let request = AIUserRequestV1 {
            schema_version: 1,
            profile_id: profile_id.to_owned(),
            feature: intent.feature,
            question: intent.question.clone(),
            aggregate: intent.aggregate.clone(),
        };
        request.validate().map_err(|_| PluginHostErrorV1::InvalidOutput)?;
        Ok(request)
    }).collect::<Result<Vec<_>, PluginHostErrorV1>>()?;
    let output = apply_plugin_output(datastore, manifest, output)?;
    Ok(PreparedPluginActionsV1 {
        ui: output.ui,
        writes: output.writes,
        network_previews,
        ai_requests,
        destructive_confirmations: output.destructive,
    })
}

fn preview_network_intent(
    proxy: &EgressProxy,
    policy: &VerifiedPolicyV1,
    purposes: &[aw_models::EgressPurposeV1],
    intent: &PluginNetworkIntentV1,
    now: DateTime<Utc>,
    local_offset_seconds: i32,
) -> Result<EgressDecisionV1, PluginHostErrorV1> {
    let purpose = purposes.iter()
        .find(|purpose| purpose.id == intent.purpose_id && purpose.destination_id == intent.destination_id)
        .ok_or(PluginHostErrorV1::EgressPolicyUnavailable)?;
    Ok(proxy.preview(policy, EgressRequestV1 {
        schema_version: 1,
        destination_id: intent.destination_id.clone(),
        purpose_id: intent.purpose_id.clone(),
        retention_id: purpose.retention_id.clone(),
        payload: intent.payload.clone(),
    }, now, local_offset_seconds))
}

fn map_input_error(_: PluginContractErrorV1) -> PluginHostErrorV1 { PluginHostErrorV1::InvalidInput }
fn map_storage_error(_: DatastoreError) -> PluginHostErrorV1 { PluginHostErrorV1::StorageUnavailable }
