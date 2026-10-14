//! Atomic local companion projection; private companion notes have no DTO field.
//! Canonical AES IDs claim validated dedicated rows. The private source checkpoint
//! is excluded from recovery, so a new device cannot delete another device's rows.
//! Digestless legacy rows acquire a checkpoint only when their schema and timing
//! match the accepted local source; divergent legacy data requires explicit review.
use crate::{DatastoreError, DatastoreInstance};
use aw_models::{Bucket, BucketMetadata, CapturePolicy, Event};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ring::digest::{digest, SHA256};
use rusqlite::Connection;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

pub const MANUAL_COMPANION_BUCKET: &str = "aw-stopwatch-ios-companion";
pub const MANUAL_COMPANION_CLIENT: &str = "peakactivity-ios-companion";
pub const MANUAL_COMPANION_HOSTNAME: &str = "ios-companion-local";
const MAX_MANUAL_ENTRIES: usize = 10_000;
pub(crate) const MANUAL_SOURCE_CHECKPOINT_KEY: &str = "ios_manual_source_checkpoint_v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManualSourceCheckpoint {
    schema_version: u16,
    entries: Vec<[String; 2]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManualActivityEntryV1 {
    #[serde(deserialize_with = "deserialize_id")]
    pub id: String,
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub timestamp: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_duration")]
    pub duration_seconds: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ManualProjectionResultV1 {
    pub inserted: usize,
    pub corrected: usize,
    pub deleted: usize,
    pub filtered: usize,
}

fn invalid() -> DatastoreError {
    DatastoreError::InvalidImport("Invalid or conflicting local manual activity snapshot".into())
}
fn deserialize_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    CapturePolicy::canonical_manual_entry_id(&String::deserialize(deserializer)?)
        .ok_or_else(|| serde::de::Error::custom("Manual entry ID must be a UUID"))
}
fn deserialize_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let duration = u32::deserialize(deserializer)?;
    if (1..=86_400).contains(&duration) {
        Ok(duration)
    } else {
        Err(serde::de::Error::custom(
            "Manual duration must be between 1 and 86400 seconds",
        ))
    }
}
fn deserialize_timestamp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DateTime<Utc>, D::Error> {
    DateTime::parse_from_rfc3339(&String::deserialize(deserializer)?)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| serde::de::Error::custom("Manual timestamp must be RFC3339"))
}

pub(crate) fn validate_snapshot(
    entries: &[ManualActivityEntryV1],
) -> Result<Vec<Event>, DatastoreError> {
    if entries.len() > MAX_MANUAL_ENTRIES {
        return Err(invalid());
    }
    let mut ids = HashSet::new();
    entries.iter().map(|entry| {
        let id = CapturePolicy::canonical_manual_entry_id(&entry.id).ok_or_else(invalid)?;
        if !ids.insert(id.clone()) || !(1..=86_400).contains(&entry.duration_seconds) { return Err(invalid()); }
        let duration = Duration::seconds(i64::from(entry.duration_seconds));
        let end = entry.timestamp.checked_add_signed(duration).ok_or_else(invalid)?;
        if entry.timestamp.timestamp_nanos_opt().is_none() || end.timestamp_nanos_opt().is_none() { return Err(invalid()); }
        let canonical = serde_json::to_vec(&json!({"id":id,"timestamp":entry.timestamp.to_rfc3339_opts(SecondsFormat::AutoSi,true),"duration_seconds":entry.duration_seconds}))
            .map_err(|_| invalid())?;
        let mut source = b"PeakActivity:ManualActivitySourceV1\0".to_vec(); source.extend(canonical);
        let hash: String = digest(&SHA256,&source).as_ref().iter().map(|byte|format!("{byte:02x}")).collect();
        Ok(Event::new(entry.timestamp,duration,json!({"label":"Manual activity","running":false,"manual_entry_id":id,"manual_source_sha256":hash}).as_object().unwrap().clone()))
    }).collect()
}

fn projection_shape(event: &Event) -> bool {
    event.data.get("label").and_then(Value::as_str) == Some("Manual activity")
        && event.data.get("running").and_then(Value::as_bool) == Some(false)
        && event.data.keys().all(|key| {
            matches!(
                key.as_str(),
                "label" | "running" | "manual_entry_id" | "manual_source_sha256"
            )
        })
        && event.data.get("manual_source_sha256").is_none_or(|value| {
            value
                .as_str()
                .is_some_and(CapturePolicy::valid_manual_source_sha256)
        })
}

impl DatastoreInstance {
    fn manual_source_checkpoint(
        &self,
        conn: &Connection,
    ) -> Result<BTreeMap<String, String>, DatastoreError> {
        let raw = match self.get_key_value(conn, MANUAL_SOURCE_CHECKPOINT_KEY) {
            Ok(value) => value,
            Err(DatastoreError::NoSuchKey(_)) => return Ok(BTreeMap::new()),
            Err(error) => return Err(error),
        };
        if raw.len() > MAX_MANUAL_ENTRIES * 120 + 128 || !raw.trim_start().starts_with('{') {
            return Err(invalid());
        }
        let checkpoint: ManualSourceCheckpoint =
            serde_json::from_str(&raw).map_err(|_| invalid())?;
        if checkpoint.schema_version != 1 || checkpoint.entries.len() > MAX_MANUAL_ENTRIES {
            return Err(invalid());
        }
        let mut entries = BTreeMap::new();
        for [id, hash] in checkpoint.entries {
            if CapturePolicy::canonical_manual_entry_id(&id).as_deref() != Some(id.as_str())
                || !CapturePolicy::valid_manual_source_sha256(&hash)
                || entries.insert(id, hash).is_some()
            {
                return Err(invalid());
            }
        }
        Ok(entries)
    }

    pub(crate) fn reconcile_manual_projection(
        &mut self,
        conn: &Connection,
        input: Vec<Event>,
        filtered: Vec<Option<Event>>,
    ) -> Result<ManualProjectionResultV1, DatastoreError> {
        let previous_source = self.manual_source_checkpoint(conn)?;
        let exists = match self.get_bucket(MANUAL_COMPANION_BUCKET) {
            Ok(bucket)
                if bucket._type == "general.stopwatch"
                    && bucket.client == MANUAL_COMPANION_CLIENT
                    && bucket.hostname == MANUAL_COMPANION_HOSTNAME
                    && bucket.data.is_empty() =>
            {
                true
            }
            Ok(_) => return Err(invalid()),
            Err(DatastoreError::NoSuchBucket(_)) => false,
            Err(error) => return Err(error),
        };
        let mut owned = BTreeMap::new();
        let mut seen = HashSet::new();
        let mut unmanaged = HashSet::new();
        if exists {
            let events = self.get_events_unclipped(
                conn,
                MANUAL_COMPANION_BUCKET,
                None,
                None,
                Some((MAX_MANUAL_ENTRIES + 1) as u64),
            )?;
            if events.len() > MAX_MANUAL_ENTRIES {
                return Err(invalid());
            }
            for event in events {
                let Some(id) = event.data.get("manual_entry_id") else {
                    continue;
                };
                let id = id
                    .as_str()
                    .and_then(CapturePolicy::canonical_manual_entry_id)
                    .ok_or_else(invalid)?;
                if !seen.insert(id.clone()) {
                    return Err(invalid());
                }
                if projection_shape(&event) {
                    owned.insert(id, event);
                } else {
                    unmanaged.insert(id);
                }
            }
        }
        let requested = input
            .iter()
            .map(|event| event.data["manual_entry_id"].as_str().unwrap().to_owned())
            .collect::<HashSet<_>>();
        let mut inserts = Vec::new();
        let mut corrections = Vec::new();
        let mut next_source = BTreeMap::new();
        let mut result = ManualProjectionResultV1::default();
        for (original, next) in input.into_iter().zip(filtered) {
            let id = original.data["manual_entry_id"].as_str().unwrap();
            if unmanaged.contains(id) {
                return Err(invalid());
            }
            let Some(mut next) = next else {
                if let Some(hash) = previous_source.get(id) {
                    next_source.insert(id.to_owned(), hash.clone());
                }
                result.filtered += 1;
                continue;
            };
            let hash = original.data["manual_source_sha256"]
                .as_str()
                .ok_or_else(invalid)?;
            next_source.insert(id.to_owned(), hash.to_owned());
            // Unchanged local state must not reverse a newer shared correction or deletion.
            if previous_source.get(id).map(String::as_str) == Some(hash) {
                continue;
            }
            if let Some(current) = owned.get(id) {
                // An unchanged AES source must not overwrite newer peer corrections.
                if current.data.get("manual_source_sha256") == next.data.get("manual_source_sha256")
                {
                    continue;
                }
                // Legacy rows have no source checkpoint; seed only an exact timing match.
                if !current.data.contains_key("manual_source_sha256")
                    && (current.timestamp != next.timestamp || current.duration != next.duration)
                {
                    return Err(invalid());
                }
                next.id = current.id;
                corrections.push(next);
            } else {
                inserts.push(next);
            }
        }
        let deletes = owned
            .iter()
            .filter(|(id, _)| previous_source.contains_key(*id) && !requested.contains(*id))
            .map(|(_, event)| event.id.ok_or_else(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        result.inserted = inserts.len();
        result.corrected = corrections.len();
        result.deleted = deletes.len();
        let source_changed = previous_source != next_source;
        if result.inserted + result.corrected + result.deleted == 0 && !source_changed {
            return Ok(result);
        }
        let checkpoint = serde_json::to_string(&ManualSourceCheckpoint {
            schema_version: 1,
            entries: next_source
                .into_iter()
                .map(|(id, hash)| [id, hash])
                .collect(),
        })
        .map_err(|_| invalid())?;
        let applied = crate::datastore::with_savepoint(conn, "companion_manual_projection", || {
            if !exists {
                self.create_bucket(
                    conn,
                    Bucket {
                        bid: None,
                        id: MANUAL_COMPANION_BUCKET.into(),
                        _type: "general.stopwatch".into(),
                        client: MANUAL_COMPANION_CLIENT.into(),
                        hostname: MANUAL_COMPANION_HOSTNAME.into(),
                        created: None,
                        data: Default::default(),
                        metadata: BucketMetadata::default(),
                        events: None,
                        last_updated: None,
                    },
                )?;
            }
            if !inserts.is_empty() {
                self.insert_events(conn, MANUAL_COMPANION_BUCKET, inserts)?;
            }
            if !corrections.is_empty() {
                self.correct_events(conn, MANUAL_COMPANION_BUCKET, &corrections, "ios-companion")?;
            }
            if !deletes.is_empty() {
                self.delete_events_by_id(conn, MANUAL_COMPANION_BUCKET, deletes)?;
            }
            if source_changed {
                conn.execute(
                    "INSERT OR REPLACE INTO key_value(key,value,last_modified) VALUES (?1,?2,?3)",
                    rusqlite::params![
                        MANUAL_SOURCE_CHECKPOINT_KEY,
                        checkpoint,
                        Utc::now().timestamp()
                    ],
                )
                .map_err(|_| {
                    DatastoreError::InternalError(
                        "The private manual source checkpoint could not be saved atomically".into(),
                    )
                })?;
            }
            Ok(result)
        });
        // Inner operations may have updated the cache before an outer rollback.
        self.reload_buckets(conn)?;
        applied
    }
}
