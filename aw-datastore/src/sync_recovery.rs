//! Intrinsic recovery checks shared by browsing and installation; target privacy gates stay local.
use crate::{DatastoreError, SyncRecoveryStateV1};
use aw_models::{BucketsExport, SyncOperationKindV1};
use aw_sync_e2ee::SyncOperationV1;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::DateTime;
use ring::digest::{digest, SHA256};
use std::collections::{BTreeMap, BTreeSet};

pub fn validate_sync_recovery_state_v1(
    state: &SyncRecoveryStateV1,
    activity: &BucketsExport,
    epoch: u64,
) -> Result<(), DatastoreError> {
    let invalid = || DatastoreError::InvalidImport("Sync recovery continuity is invalid".into());
    if state.schema_version != 1 || state.key_epoch != epoch {
        return Err(invalid());
    }
    if let Some(policy) = &state.policy {
        crate::validate_sync_recovery_policy_v1(policy)?;
    }
    crate::backup_lifecycle::admitted_backup_deletion_facts(&state.backup_deletions)?;
    let mut buckets = BTreeMap::new();
    let mut activity_ids = BTreeSet::new();
    let mut event_rows = BTreeSet::new();
    for bucket in activity.buckets.values() {
        if bucket.id.trim().is_empty() || buckets.insert(bucket.id.as_str(), bucket).is_some() {
            return Err(invalid());
        }
        if let Some(events) = &bucket.events {
            if events.has_unparsed() {
                return Err(invalid());
            }
            for event in events.iter() {
                crate::datastore::event_storage_times(event)?;
                if let Some(id) = event.id {
                    if id <= 0 || !activity_ids.insert(id) {
                        return Err(invalid());
                    }
                    event_rows.insert((bucket.id.as_str(), id as u64));
                }
            }
        }
    }
    let mut trusted = BTreeSet::new();
    for peer in &state.trusted_devices {
        if !trusted.insert(peer.device_id) || DateTime::parse_from_rfc3339(&peer.paired_at).is_err()
        {
            return Err(invalid());
        }
    }
    let mut bucket_ids = BTreeMap::new();
    let mut local_ids = BTreeSet::new();
    for mapping in &state.bucket_mappings {
        mapping.descriptor.validate().map_err(|_| invalid())?;
        if !local_ids.insert(mapping.local_bucket_id.as_str())
            || bucket_ids
                .insert(mapping.sync_bucket_id, mapping.local_bucket_id.as_str())
                .is_some()
        {
            return Err(invalid());
        }
        if let Some(bucket) = buckets.get(mapping.local_bucket_id.as_str()) {
            if bucket._type != mapping.descriptor.bucket_type
                || bucket.client != mapping.descriptor.client
                || bucket
                    .data
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<BTreeMap<_, _>>()
                    != mapping.descriptor.data
            {
                return Err(invalid());
            }
        } else if state
            .event_mappings
            .iter()
            .any(|e| e.sync_bucket_id == mapping.sync_bucket_id && !e.deleted)
        {
            return Err(invalid());
        }
    }
    let mut events = BTreeSet::new();
    let mut local_events = BTreeSet::new();
    for mapping in &state.event_mappings {
        if mapping
            .local_event_id
            .is_some_and(|id| !local_events.insert((mapping.local_bucket_id.as_str(), id)))
            || mapping.origin_event_id == 0
            || mapping.origin_event_id > i64::MAX as u64
            || mapping
                .local_event_id
                .is_some_and(|id| id == 0 || id > i64::MAX as u64)
            || !events.insert((mapping.origin_device_id, mapping.origin_event_id))
            || bucket_ids.get(&mapping.sync_bucket_id) != Some(&mapping.local_bucket_id.as_str())
            || (!mapping.deleted
                && mapping
                    .local_event_id
                    .is_none_or(|id| !event_rows.contains(&(mapping.local_bucket_id.as_str(), id))))
        {
            return Err(invalid());
        }
    }
    let mut counters = BTreeMap::new();
    for counter in &state.counters {
        if counter.last_counter == 0
            || counter.last_counter > i64::MAX as u64
            || counters
                .insert(counter.device_id, counter.last_counter)
                .is_some()
        {
            return Err(invalid());
        }
    }
    let mut operations = BTreeSet::new();
    let mut tombstones = BTreeSet::new();
    let mut forgets = Vec::new();
    let mut operation_bytes = 0usize;
    if state.operations.len() > 100000 {
        return Err(invalid());
    }
    for stored in &state.operations {
        operation_bytes = operation_bytes
            .checked_add(stored.operation_json.len())
            .ok_or_else(invalid)?;
        if operation_bytes > aw_sync_e2ee::MAX_BACKUP_BUNDLE_BYTES {
            return Err(invalid());
        }
        if stored.operation_json.len() > aw_models::SYNC_MAX_CHUNK_BYTES
            || stored.key_epoch != epoch
            || stored.counter == 0
            || stored.counter > i64::MAX as u64
            || !trusted.contains(&stored.device_id)
            || counters
                .get(&stored.device_id)
                .is_none_or(|last| *last < stored.counter)
            || !operations.insert((stored.device_id, stored.counter))
            || digest(&SHA256, stored.operation_json.as_bytes()).as_ref() != stored.content_hash
        {
            return Err(invalid());
        }
        let op: SyncOperationV1 =
            serde_json::from_str(&stored.operation_json).map_err(|_| invalid())?;
        op.validate().map_err(|_| invalid())?;
        if op.device_id != URL_SAFE_NO_PAD.encode(stored.device_id) || op.counter != stored.counter
        {
            return Err(invalid());
        }
        if op.kind == SyncOperationKindV1::Tombstone {
            let origin: [u8; 16] = URL_SAFE_NO_PAD
                .decode(&op.origin_device_id)
                .map_err(|_| invalid())?
                .try_into()
                .map_err(|_| invalid())?;
            tombstones.insert((origin, op.local_event_id.ok_or_else(invalid)?, op.counter));
        }
        if op.kind == SyncOperationKindV1::BackupForget {
            forgets.push(op);
        }
    }
    let completed =
        aw_sync_e2ee::assemble_backup_forget_operations(&forgets).map_err(|_| invalid())?;
    let known = state
        .backup_deletions
        .iter()
        .map(|fact| ((&fact.vault_id, &fact.key_epoch, &fact.snapshot_id), fact))
        .collect::<BTreeMap<_, _>>();
    if completed.iter().any(|fact| {
        known
            .get(&(&fact.vault_id, &fact.key_epoch, &fact.snapshot_id))
            .copied()
            != Some(fact)
    }) {
        return Err(invalid());
    }
    let mut heads = BTreeSet::new();
    for head in &state.stream_heads {
        if head.revision == 0
            || head.revision > i64::MAX as u64
            || !trusted.contains(&head.device_id)
            || !heads.insert(head.device_id)
        {
            return Err(invalid());
        }
    }
    let mut acks = BTreeSet::new();
    for ack in &state.tombstone_acknowledgements {
        if !trusted.contains(&ack.device_id)
            || !tombstones.contains(&(
                ack.origin_device_id,
                ack.local_event_id,
                ack.tombstone_counter,
            ))
            || !acks.insert((
                ack.origin_device_id,
                ack.local_event_id,
                ack.tombstone_counter,
                ack.device_id,
            ))
            || DateTime::parse_from_rfc3339(&ack.acknowledged_at).is_err()
        {
            return Err(invalid());
        }
    }
    Ok(())
}
