use crate::{DatastoreError, DatastoreInstance};
use aw_models::{
    CapturePolicy, EgressUserPolicyV1, SignedEgressPolicyBundleV1, SyncCapturePreferencesV1,
    SyncPolicyContractErrorV1 as Error, SyncPolicyValueV1,
};
use aw_models::{
    SyncPolicyCandidatePageV1, SyncPolicyCandidateV1, SyncPolicyChoiceRequestV1,
    SyncPolicyChoiceResultV1, SyncPolicyDecisionV1, SyncPolicyPreviewV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::digest::{digest, Context, SHA256};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;

pub(crate) const DECISION_PREFIX: &str = "peakactivity.sync_policy_decisions";
const RECOVERY_PREFIX: &str = "peakactivity.sync_policy_decisions.recovery.";
const MAX_CURRENT: usize = 100_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decisions {
    schema_version: u16,
    key_epoch: u64,
    field: String,
    candidate_ids: Vec<String>,
}
struct Candidate {
    meta: SyncPolicyCandidateV1,
    value_sha256: String,
}
struct Current {
    epoch: u64,
    vault: [u8; 16],
    local: [u8; 16],
    candidates: Vec<Candidate>,
}

pub struct SyncPolicyActivationContextV1<'a> {
    pub field: &'a str,
    pub proposed: &'a SyncPolicyValueV1,
    pub current_bundle: Option<&'a SignedEgressPolicyBundleV1>,
    pub current_user: &'a EgressUserPolicyV1,
}
pub struct SyncPolicyActivationGateV1(
    Box<
        dyn for<'a> FnOnce(&SyncPolicyActivationContextV1<'a>) -> Result<(), DatastoreError> + Send,
    >,
);
impl SyncPolicyActivationGateV1 {
    pub fn new(
        check: impl for<'a> FnOnce(&SyncPolicyActivationContextV1<'a>) -> Result<(), DatastoreError>
            + Send
            + 'static,
    ) -> Self {
        Self(Box::new(check))
    }
}
impl fmt::Debug for SyncPolicyActivationGateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<trusted policy activation gate>")
    }
}
pub(crate) struct ChoiceEffects {
    pub response: SyncPolicyChoiceResultV1,
    pub capture: Option<CapturePolicy>,
    pub privacy: Option<crate::privacy_filter::PrivacyFilterEngine>,
}

fn hash<T: Serialize>(value: &T) -> Result<String, DatastoreError> {
    struct Writer(Context);
    impl std::io::Write for Writer {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.update(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = Writer(Context::new(&SHA256));
    w.0.update(b"PeakActivity:policy-review:v1\0");
    serde_json::to_writer(&mut w, value).map_err(|_| policy_error())?;
    Ok(w.0
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn raw_key(
    ds: &DatastoreInstance,
    conn: &Connection,
    key: &str,
) -> Result<Option<String>, DatastoreError> {
    match ds.get_key_value(conn, key) {
        Ok(v) => Ok(Some(v)),
        Err(DatastoreError::NoSuchKey(_)) => Ok(None),
        Err(e) => Err(e),
    }
}
fn decision_key(field: &str) -> String {
    format!("{DECISION_PREFIX}.{field}")
}
fn decisions(
    ds: &DatastoreInstance,
    conn: &Connection,
    field: &str,
    epoch: u64,
) -> Result<Vec<String>, DatastoreError> {
    let Some(raw) = raw_key(ds, conn, &decision_key(field))? else {
        return Ok(Vec::new());
    };
    if raw.len() > aw_models::SYNC_MAX_CHUNK_BYTES || !raw.trim_start().starts_with('{') {
        return Err(policy_error());
    }
    let d: Decisions = serde_json::from_str(&raw).map_err(|_| policy_error())?;
    if d.schema_version != 1
        || d.key_epoch == 0
        || d.field != field
        || d.candidate_ids.len() > MAX_CURRENT
        || d.candidate_ids
            .iter()
            .any(|id| !aw_models::valid_lower_hex(id, 64))
        || d.candidate_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(policy_error());
    }
    Ok(if d.key_epoch == epoch {
        d.candidate_ids
    } else {
        Vec::new()
    })
}

fn current(ds: &DatastoreInstance, conn: &Connection) -> Result<Current, DatastoreError> {
    let identity = ds
        .get_sync_device_identity(conn)?
        .ok_or_else(policy_error)?;
    let material = ds.get_sync_key_material(conn)?.ok_or_else(policy_error)?;
    let epoch = material.key_epoch();
    let vault = *material.vault_id();
    let history: usize = conn
        .query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM sync_operations WHERE key_epoch=?1 LIMIT 100001)",
            [epoch as i64],
            |row| row.get(0),
        )
        .map_err(|_| policy_error())?;
    if history > MAX_CURRENT {
        return Err(policy_error());
    }
    let mut statement=conn.prepare_cached("WITH latest AS (
        SELECT o.device_id,j.key AS field,MAX(o.counter) AS counter FROM sync_operations o,json_each(o.operation_json,'$.fields') j
        WHERE o.key_epoch=?1 AND json_extract(o.operation_json,'$.kind')='policy_change' GROUP BY o.device_id,j.key)
        SELECT o.device_id,o.counter,o.operation_json,o.content_hash,l.field FROM latest l JOIN sync_operations o ON o.device_id=l.device_id AND o.counter=l.counter AND o.key_epoch=?1 ORDER BY l.field,o.device_id,o.counter LIMIT 100001").map_err(|_|policy_error())?;
    let mut rows = statement
        .query([epoch as i64])
        .map_err(|_| policy_error())?;
    let mut candidates = Vec::new();
    while let Some(row) = rows.next().map_err(|_| policy_error())? {
        if candidates.len() == MAX_CURRENT {
            return Err(policy_error());
        }
        let device: Vec<u8> = row.get(0).map_err(|_| policy_error())?;
        let counter: i64 = row.get(1).map_err(|_| policy_error())?;
        let stored_hash: Vec<u8> = row.get(3).map_err(|_| policy_error())?;
        let field: String = row.get(4).map_err(|_| policy_error())?;
        let raw = row
            .get_ref(2)
            .map_err(|_| policy_error())?
            .as_str()
            .map_err(|_| policy_error())?;
        if device.len() != 16
            || counter <= 0
            || raw.len() > aw_models::SYNC_MAX_CHUNK_BYTES
            || digest(&SHA256, raw.as_bytes()).as_ref() != stored_hash
        {
            return Err(policy_error());
        }
        let op: aw_sync_e2ee::SyncOperationV1 =
            serde_json::from_str(raw).map_err(|_| policy_error())?;
        op.validate().map_err(|_| policy_error())?;
        validate_operation(&op)?;
        if URL_SAFE_NO_PAD
            .decode(&op.device_id)
            .map_err(|_| policy_error())?
            != device
            || op.counter != counter as u64
            || op.kind != aw_models::SyncOperationKindV1::PolicyChange
        {
            return Err(policy_error());
        }
        let value: SyncPolicyValueV1 =
            serde_json::from_value(op.fields.get(&field).ok_or_else(policy_error)?.clone())
                .map_err(|_| policy_error())?;
        let candidate_id = hash(&(
            vault,
            epoch,
            &field,
            &op.device_id,
            op.counter,
            &stored_hash,
        ))?;
        candidates.push(Candidate {
            meta: SyncPolicyCandidateV1 {
                candidate_id,
                field,
                device_id: op.device_id,
                counter: op.counter.to_string(),
                policy_version: op.policy_version.ok_or_else(policy_error)?.to_string(),
                recovery_source: None,
            },
            value_sha256: hash(&value)?,
        });
    }
    for entry in recovery_entries(conn)? {
        if entry.source.vault_id == URL_SAFE_NO_PAD.encode(vault)
            && entry.source.key_epoch == epoch.to_string()
        {
            candidates.push(recovery_candidate(&entry)?);
        }
    }
    if candidates.len() > MAX_CURRENT {
        return Err(policy_error());
    }
    candidates.sort_by(|a, b| a.meta.candidate_id.cmp(&b.meta.candidate_id));
    Ok(Current {
        epoch,
        vault,
        local: *identity.device_id(),
        candidates,
    })
}
fn is_remote(candidate: &Candidate, state: &Current) -> bool {
    candidate.meta.recovery_source.is_some()
        || candidate.meta.device_id != URL_SAFE_NO_PAD.encode(state.local)
}
fn pending(
    ds: &DatastoreInstance,
    conn: &Connection,
    state: &Current,
    candidate: &Candidate,
) -> Result<bool, DatastoreError> {
    Ok(is_remote(candidate, state)
        && !decisions(ds, conn, &candidate.meta.field, state.epoch)?
            .contains(&candidate.meta.candidate_id)
        && candidate.value_sha256 != hash(&project(ds, conn, &candidate.meta.field)?)?)
}
pub(crate) fn list_candidates(
    ds: &DatastoreInstance,
    conn: &Connection,
    after: Option<&str>,
    limit: usize,
) -> Result<SyncPolicyCandidatePageV1, DatastoreError> {
    if !(1..=256).contains(&limit) || after.is_some_and(|id| !aw_models::valid_lower_hex(id, 64)) {
        return Err(policy_error());
    }
    let state = current(ds, conn)?;
    let mut page = Vec::new();
    let mut more = false;
    for candidate in &state.candidates {
        if after.is_some_and(|id| candidate.meta.candidate_id.as_str() <= id)
            || !pending(ds, conn, &state, candidate)?
        {
            continue;
        }
        if page.len() == limit {
            more = true;
            break;
        }
        page.push(candidate.meta.clone());
    }
    let next_cursor = if more {
        page.last().map(|candidate| candidate.candidate_id.clone())
    } else {
        None
    };
    Ok(SyncPolicyCandidatePageV1 {
        schema_version: 1,
        candidates: page,
        next_cursor,
    })
}
fn selected_value(
    conn: &Connection,
    candidate: &Candidate,
    epoch: u64,
) -> Result<SyncPolicyValueV1, DatastoreError> {
    if let Some(source) = &candidate.meta.recovery_source {
        let raw: String = conn
            .query_row(
                "SELECT value FROM key_value WHERE key=?1",
                [recovery_key(source, &candidate.meta.field)],
                |row| row.get(0),
            )
            .map_err(|_| policy_error())?;
        let entry: aw_models::SyncRecoveryPolicyCandidateV1 =
            serde_json::from_str(&raw).map_err(|_| policy_error())?;
        validate_recovery_entry(&entry)?;
        if recovery_candidate(&entry)?.meta.candidate_id != candidate.meta.candidate_id {
            return Err(policy_error());
        }
        return Ok(entry.value);
    }
    let device = URL_SAFE_NO_PAD
        .decode(&candidate.meta.device_id)
        .map_err(|_| policy_error())?;
    let counter: u64 = candidate.meta.counter.parse().map_err(|_| policy_error())?;
    let raw:String=conn.query_row("SELECT operation_json FROM sync_operations WHERE device_id=?1 AND counter=?2 AND key_epoch=?3",rusqlite::params![device,counter as i64,epoch as i64],|r|r.get(0)).map_err(|_|policy_error())?;
    let op: aw_sync_e2ee::SyncOperationV1 =
        serde_json::from_str(&raw).map_err(|_| policy_error())?;
    serde_json::from_value(
        op.fields
            .get(&candidate.meta.field)
            .ok_or_else(policy_error)?
            .clone(),
    )
    .map_err(|_| policy_error())
}
fn make_preview(
    ds: &DatastoreInstance,
    conn: &Connection,
    state: &Current,
    candidate: &Candidate,
) -> Result<SyncPolicyPreviewV1, DatastoreError> {
    if !pending(ds, conn, state, candidate)? {
        return Err(policy_error());
    }
    let field = &candidate.meta.field;
    let keys = if matches!(
        field.as_str(),
        "settings.classes" | "settings.category_sets" | "settings.active_set_ids"
    ) {
        vec![
            "settings.classes",
            "settings.category_sets",
            "settings.active_set_ids",
        ]
    } else if field == "capture.minimization" {
        vec!["peakactivity.capture_policy"]
    } else if field.starts_with("egress.") {
        vec!["egress.policy_state", "egress.user_policy"]
    } else {
        vec![field.as_str()]
    };
    let stored = keys
        .into_iter()
        .map(|key| raw_key(ds, conn, key))
        .collect::<Result<Vec<_>, _>>()?;
    let identities = state
        .candidates
        .iter()
        .filter(|c| c.meta.field == *field)
        .map(|c| (&c.meta.candidate_id, &c.value_sha256))
        .collect::<Vec<_>>();
    let reviewed = decisions(ds, conn, field, state.epoch)?;
    let current = project(ds, conn, field)?;
    let expected_review_sha256 = hash(&(
        ds.policy_context,
        state.vault,
        state.epoch,
        field,
        &stored,
        &current,
        identities,
        reviewed,
    ))?;
    Ok(SyncPolicyPreviewV1 {
        schema_version: 1,
        candidate: candidate.meta.clone(),
        current,
        proposed: selected_value(conn, candidate, state.epoch)?,
        expected_review_sha256,
    })
}
pub(crate) fn preview_candidate(
    ds: &DatastoreInstance,
    conn: &Connection,
    id: &str,
) -> Result<SyncPolicyPreviewV1, DatastoreError> {
    if !aw_models::valid_lower_hex(id, 64) {
        return Err(policy_error());
    }
    let state = current(ds, conn)?;
    let candidate = state
        .candidates
        .iter()
        .find(|c| c.meta.candidate_id == id)
        .ok_or_else(policy_error)?;
    make_preview(ds, conn, &state, candidate)
}
pub(crate) fn choose(
    ds: &DatastoreInstance,
    conn: &Connection,
    request: SyncPolicyChoiceRequestV1,
    gate: Option<SyncPolicyActivationGateV1>,
    cached_capture: Option<&CapturePolicy>,
) -> Result<ChoiceEffects, DatastoreError> {
    request.validate().map_err(|_| policy_error())?;
    crate::datastore::with_savepoint(conn, "sync_policy_choice", || {
        let state = current(ds, conn)?;
        let candidate = state
            .candidates
            .iter()
            .find(|c| c.meta.candidate_id == request.candidate_id)
            .ok_or_else(policy_error)?;
        let preview = make_preview(ds, conn, &state, candidate)?;
        if preview.expected_review_sha256 != request.expected_review_sha256 {
            return Err(DatastoreError::InvalidImport(
                "The policy changed after review".into(),
            ));
        }
        let field = &preview.candidate.field;
        let mut capture = None;
        let mut privacy = None;
        let applied = request.decision == SyncPolicyDecisionV1::AcceptRemote;
        if applied {
            if field == "capture.minimization" {
                let mut base = if let Some(current) = cached_capture {
                    current.clone()
                } else {
                    match raw_key(ds, conn, "peakactivity.capture_policy")? {
                        Some(raw) => serde_json::from_str::<CapturePolicy>(&raw)
                            .map_err(|_| policy_error())?,
                        None => CapturePolicy::default(),
                    }
                };
                base.validate().map_err(|_| policy_error())?;
                let preferences = if preview.proposed.present {
                    serde_json::from_value::<SyncCapturePreferencesV1>(
                        preview.proposed.value.clone(),
                    )
                    .map_err(|_| policy_error())?
                } else {
                    SyncCapturePreferencesV1::from_policy(&CapturePolicy::default())
                };
                base = preferences.apply_to(&base).map_err(|_| policy_error())?;
                base.revision = base.revision.checked_add(1).ok_or_else(policy_error)?;
                base.effective_from = chrono::Utc::now();
                ds.insert_key_value(
                    conn,
                    "peakactivity.capture_policy",
                    &serde_json::to_string(&base).map_err(|_| policy_error())?,
                )?;
                capture = Some(base);
            } else if field.starts_with("egress.") {
                let gate = gate.ok_or_else(|| {
                    DatastoreError::InvalidImport("Trusted Firewall activation is required".into())
                })?;
                let current_bundle = ds.get_egress_policy_state(conn)?.map(|(bundle, _)| bundle);
                let current_user = ds.get_egress_user_policy(conn)?;
                (gate.0)(&SyncPolicyActivationContextV1 {
                    field,
                    proposed: &preview.proposed,
                    current_bundle: current_bundle.as_ref(),
                    current_user: &current_user,
                })?;
                if field == "egress.signed_bundle" {
                    if !preview.proposed.present {
                        return Err(policy_error());
                    }
                    let bundle: SignedEgressPolicyBundleV1 =
                        serde_json::from_value(preview.proposed.value.clone())
                            .map_err(|_| policy_error())?;
                    ds.store_egress_policy_state(conn, &bundle, &current_user)?;
                } else {
                    let user = if preview.proposed.present {
                        serde_json::from_value::<EgressUserPolicyV1>(preview.proposed.value.clone())
                            .map_err(|_| policy_error())?
                    } else {
                        EgressUserPolicyV1 {
                            schema_version: 1,
                            user_rules: Vec::new(),
                            safe_zone_patterns: Vec::new(),
                            after_hours: None,
                        }
                    };
                    ds.store_egress_user_policy(conn, &user)?;
                }
            } else {
                if field == "settings.privacy_filters" {
                    privacy = Some(if preview.proposed.present {
                        crate::privacy_filter::PrivacyFilterEngine::from_json(
                            &preview.proposed.value.to_string(),
                        )
                        .map_err(|_| policy_error())?
                    } else {
                        crate::privacy_filter::PrivacyFilterEngine::new(Vec::new())
                    });
                }
                if preview.proposed.present {
                    ds.insert_key_value(conn, field, &preview.proposed.value.to_string())?;
                } else {
                    ds.delete_key_value(conn, field)?;
                }
            }
        }
        let mut ids = state
            .candidates
            .iter()
            .filter(|c| c.meta.field == *field && is_remote(c, &state))
            .map(|c| c.meta.candidate_id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        let decision = Decisions {
            schema_version: 1,
            key_epoch: state.epoch,
            field: field.clone(),
            candidate_ids: ids,
        };
        aw_models::serialized_size(&decision, aw_models::SYNC_MAX_CHUNK_BYTES)
            .map_err(|_| policy_error())?;
        ds.insert_key_value(
            conn,
            &decision_key(field),
            &serde_json::to_string(&decision).map_err(|_| policy_error())?,
        )?;
        Ok(ChoiceEffects {
            response: SyncPolicyChoiceResultV1 {
                schema_version: 1,
                field: field.clone(),
                decision: request.decision,
                applied,
            },
            capture,
            privacy,
        })
    })
}

fn policy_error() -> DatastoreError {
    DatastoreError::InvalidImport(
        "The settings change cannot be represented by the sync policy contract".into(),
    )
}

pub(crate) fn validate_operation(
    operation: &aw_sync_e2ee::SyncOperationV1,
) -> Result<(), DatastoreError> {
    if operation.kind == aw_models::SyncOperationKindV1::PolicyChange {
        for (field, raw) in &operation.fields {
            let value: SyncPolicyValueV1 =
                serde_json::from_value(raw.clone()).map_err(|_| policy_error())?;
            validate_sync_policy_field_v1(field, &value).map_err(|_| policy_error())?;
        }
    }
    Ok(())
}

pub(crate) fn mutate_key(
    ds: &DatastoreInstance,
    conn: &Connection,
    key: &str,
    mutation: impl FnOnce() -> Result<(), DatastoreError>,
) -> Result<(), DatastoreError> {
    let fields = if PORTABLE_SETTING_KEYS_V1.contains(&key) {
        vec![key]
    } else {
        match key {
            "peakactivity.capture_policy" => vec!["capture.minimization"],
            "egress.policy_state" => vec!["egress.signed_bundle", "egress.user_policy"],
            "egress.user_policy" => vec!["egress.user_policy"],
            _ => Vec::new(),
        }
    };
    if !ds.encrypted || fields.is_empty() || !ds.sync_journal_active(conn)? {
        return mutation();
    }
    crate::datastore::with_savepoint(conn, "sync_policy_write", || {
        let before = fields
            .iter()
            .map(|field| project(ds, conn, field))
            .collect::<Result<Vec<_>, _>>()?;
        mutation()?;
        for (field, before) in fields.into_iter().zip(before) {
            let after = project(ds, conn, field)?;
            if after != before {
                record(ds, conn, field, after)?;
            }
        }
        Ok(())
    })
}

pub(crate) fn seed_current(
    ds: &DatastoreInstance,
    conn: &Connection,
) -> Result<(), DatastoreError> {
    for field in PORTABLE_SETTING_KEYS_V1.into_iter().chain([
        "capture.minimization",
        "egress.user_policy",
        "egress.signed_bundle",
    ]) {
        record(ds, conn, field, project(ds, conn, field)?)?;
    }
    Ok(())
}

fn project(
    ds: &DatastoreInstance,
    conn: &Connection,
    field: &str,
) -> Result<SyncPolicyValueV1, DatastoreError> {
    let stored = |key| match ds.get_key_value(conn, key) {
        Ok(raw) => serde_json::from_str(&raw)
            .map(|value| SyncPolicyValueV1 {
                schema_version: 1,
                present: true,
                value,
            })
            .map_err(|_| policy_error()),
        Err(DatastoreError::NoSuchKey(_)) => Ok(SyncPolicyValueV1 {
            schema_version: 1,
            present: false,
            value: Value::Null,
        }),
        Err(error) => Err(error),
    };
    let encode = |value| {
        Ok(SyncPolicyValueV1 {
            schema_version: 1,
            present: true,
            value,
        })
    };
    match field {
        "capture.minimization" => {
            let current = stored("peakactivity.capture_policy")?;
            let mut policy = if current.present {
                serde_json::from_value::<CapturePolicy>(current.value)
                    .map_err(|_| policy_error())?
            } else {
                CapturePolicy::default()
            };
            policy.validate().map_err(|_| policy_error())?;
            encode(
                serde_json::to_value(SyncCapturePreferencesV1::from_policy(&policy))
                    .map_err(|_| policy_error())?,
            )
        }
        "egress.user_policy" => encode(
            serde_json::to_value(ds.get_egress_user_policy(conn)?).map_err(|_| policy_error())?,
        ),
        "egress.signed_bundle" => match ds.get_egress_policy_state(conn)? {
            Some((bundle, _)) => encode(serde_json::to_value(bundle).map_err(|_| policy_error())?),
            None => Ok(SyncPolicyValueV1 {
                schema_version: 1,
                present: false,
                value: Value::Null,
            }),
        },
        _ => stored(field),
    }
}

fn recovery_companions(field: &str) -> Vec<&str> {
    if matches!(
        field,
        "settings.classes" | "settings.category_sets" | "settings.active_set_ids"
    ) {
        vec![
            "settings.classes",
            "settings.category_sets",
            "settings.active_set_ids",
        ]
    } else if field.starts_with("egress.") {
        vec!["egress.signed_bundle", "egress.user_policy"]
    } else {
        vec![field]
    }
}

fn recovery_binding(
    values: &[aw_models::SyncRecoveryPolicyFieldV1],
    field: &str,
) -> Result<String, DatastoreError> {
    let companions = recovery_companions(field)
        .into_iter()
        .map(|scope| {
            values
                .iter()
                .find(|entry| entry.field == scope)
                .ok_or_else(policy_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    hash(&("recovery-active-values", field, companions))
}

fn projected_target(
    ds: &DatastoreInstance,
    conn: &Connection,
    reset_privacy: bool,
) -> Result<Vec<aw_models::SyncRecoveryPolicyFieldV1>, DatastoreError> {
    let mut values = PORTABLE_SETTING_KEYS_V1
        .into_iter()
        .chain([
            "capture.minimization",
            "egress.user_policy",
            "egress.signed_bundle",
        ])
        .map(|field| {
            Ok(aw_models::SyncRecoveryPolicyFieldV1 {
                field: field.into(),
                value: project(ds, conn, field)?,
            })
        })
        .collect::<Result<Vec<_>, DatastoreError>>()?;
    if reset_privacy {
        for entry in &mut values {
            if entry.field == "capture.minimization" {
                entry.value = SyncPolicyValueV1 {
                    schema_version: 1,
                    present: true,
                    value: serde_json::to_value(SyncCapturePreferencesV1::from_policy(
                        &CapturePolicy::default(),
                    ))
                    .map_err(|_| policy_error())?,
                };
            } else if entry.field == "settings.privacy_filters" {
                entry.value = SyncPolicyValueV1 {
                    schema_version: 1,
                    present: true,
                    value: serde_json::json!([]),
                };
            }
        }
    }
    values.sort_by(|a, b| a.field.cmp(&b.field));
    Ok(values)
}

fn recovery_key(source: &aw_models::SyncPolicyRecoverySourceV1, field: &str) -> String {
    format!(
        "{RECOVERY_PREFIX}{}.{}.{}.{}",
        source.vault_id, source.key_epoch, source.snapshot_id, field
    )
}
fn validate_recovery_entry(
    entry: &aw_models::SyncRecoveryPolicyCandidateV1,
) -> Result<(), DatastoreError> {
    let source = &entry.source;
    let epoch = source
        .key_epoch
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && *value <= i64::MAX as u64)
        .ok_or_else(policy_error)?;
    if entry.schema_version != 1
        || source.schema_version != 1
        || source.key_epoch != epoch.to_string()
        || [source.vault_id.as_str(), source.snapshot_id.as_str()]
            .iter()
            .any(|id| {
                URL_SAFE_NO_PAD.decode(id).map_or(true, |bytes| {
                    bytes.len() != 16 || URL_SAFE_NO_PAD.encode(bytes) != *id
                })
            })
    {
        return Err(policy_error());
    }
    validate_sync_policy_field_v1(&entry.field, &entry.value).map_err(|_| policy_error())?;
    aw_models::serialized_size(entry, aw_models::SYNC_MAX_CHUNK_BYTES)
        .map_err(|_| policy_error())?;
    Ok(())
}
fn recovery_candidate(
    entry: &aw_models::SyncRecoveryPolicyCandidateV1,
) -> Result<Candidate, DatastoreError> {
    let value_sha256 = hash(&entry.value)?;
    Ok(Candidate {
        meta: SyncPolicyCandidateV1 {
            candidate_id: hash(&(
                "recovery-snapshot",
                &entry.source,
                &entry.field,
                &value_sha256,
            ))?,
            field: entry.field.clone(),
            device_id: entry.source.snapshot_id.clone(),
            counter: "1".into(),
            policy_version: entry.source.key_epoch.clone(),
            recovery_source: Some(entry.source.clone()),
        },
        value_sha256,
    })
}
fn recovery_entries(
    conn: &Connection,
) -> Result<Vec<aw_models::SyncRecoveryPolicyCandidateV1>, DatastoreError> {
    let mut statement = conn
        .prepare_cached(
            "SELECT key,value FROM key_value WHERE key GLOB ?1 ORDER BY key LIMIT 100001",
        )
        .map_err(|_| policy_error())?;
    let rows = statement
        .query_map([format!("{RECOVERY_PREFIX}*")], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| policy_error())?;
    let mut entries = Vec::new();
    for row in rows {
        if entries.len() == MAX_CURRENT {
            return Err(policy_error());
        }
        let (key, raw) = row.map_err(|_| policy_error())?;
        if raw.len() > aw_models::SYNC_MAX_CHUNK_BYTES {
            return Err(policy_error());
        }
        let entry: aw_models::SyncRecoveryPolicyCandidateV1 =
            serde_json::from_str(&raw).map_err(|_| policy_error())?;
        validate_recovery_entry(&entry)?;
        if key != recovery_key(&entry.source, &entry.field) {
            return Err(policy_error());
        }
        entries.push(entry);
    }
    Ok(entries)
}

struct RecoveryPlan {
    summary: aw_models::SyncRecoveryPolicySummaryV1,
    entries: Vec<aw_models::SyncRecoveryPolicyCandidateV1>,
    decisions: Vec<Decisions>,
}
fn recovery_plan(
    ds: &DatastoreInstance,
    conn: &Connection,
    state: &crate::SyncRecoveryStateV1,
    vault: [u8; 16],
    epoch: u64,
    snapshot: [u8; 16],
    reset_privacy: bool,
) -> Result<RecoveryPlan, DatastoreError> {
    if state.schema_version != 1
        || state.key_epoch != epoch
        || epoch == 0
        || epoch > i64::MAX as u64
        || state.operations.len() > MAX_CURRENT
    {
        return Err(policy_error());
    }
    let target = projected_target(ds, conn, reset_privacy)?;
    let target_hashes = target
        .iter()
        .map(|entry| Ok((entry.field.as_str(), hash(&entry.value)?)))
        .collect::<Result<BTreeMap<_, _>, DatastoreError>>()?;
    let trusted = state
        .trusted_devices
        .iter()
        .map(|device| device.device_id)
        .collect::<std::collections::BTreeSet<_>>();
    if trusted.len() != state.trusted_devices.len() {
        return Err(policy_error());
    }
    let mut latest = BTreeMap::<([u8; 16], String), (u64, Candidate)>::new();
    let mut stored_ids = std::collections::BTreeSet::new();
    for stored in &state.operations {
        if stored.key_epoch != epoch
            || stored.counter == 0
            || stored.counter > i64::MAX as u64
            || stored.operation_json.len() > aw_models::SYNC_MAX_CHUNK_BYTES
            || !stored_ids.insert((stored.device_id, stored.counter))
            || digest(&SHA256, stored.operation_json.as_bytes()).as_ref() != stored.content_hash
            || !trusted.contains(&stored.device_id)
        {
            return Err(policy_error());
        }
        let op: aw_sync_e2ee::SyncOperationV1 =
            serde_json::from_str(&stored.operation_json).map_err(|_| policy_error())?;
        op.validate().map_err(|_| policy_error())?;
        validate_operation(&op)?;
        if op.device_id != URL_SAFE_NO_PAD.encode(stored.device_id) || op.counter != stored.counter
        {
            return Err(policy_error());
        }
        if op.kind != aw_models::SyncOperationKindV1::PolicyChange {
            continue;
        }
        for (field, raw) in &op.fields {
            let value: SyncPolicyValueV1 =
                serde_json::from_value(raw.clone()).map_err(|_| policy_error())?;
            let candidate = Candidate {
                meta: SyncPolicyCandidateV1 {
                    candidate_id: hash(&(
                        vault,
                        epoch,
                        field,
                        &op.device_id,
                        op.counter,
                        &stored.content_hash[..],
                    ))?,
                    field: field.clone(),
                    device_id: op.device_id.clone(),
                    counter: op.counter.to_string(),
                    policy_version: op.policy_version.ok_or_else(policy_error)?.to_string(),
                    recovery_source: None,
                },
                value_sha256: hash(&value)?,
            };
            let key = (stored.device_id, field.clone());
            if latest
                .get(&key)
                .is_none_or(|(counter, _)| *counter < op.counter)
            {
                latest.insert(key, (op.counter, candidate));
            }
        }
    }
    let mut candidates = latest
        .into_values()
        .map(|(_, candidate)| candidate)
        .collect::<Vec<_>>();
    let mut entries = Vec::new();
    let mut resolved = Vec::new();
    if let Some(policy) = &state.policy {
        validate_sync_recovery_policy_v1(policy)?;
        for entry in &policy.pending_recovery {
            if entry.source.vault_id != URL_SAFE_NO_PAD.encode(vault)
                || entry.source.key_epoch != epoch.to_string()
            {
                return Err(policy_error());
            }
            candidates.push(recovery_candidate(entry)?);
            entries.push(entry.clone());
        }
        let known = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.meta.candidate_id.as_str(),
                    candidate.meta.field.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for decision in &policy.decisions {
            if decision.candidate_ids.iter().any(|id| {
                known
                    .get(id.as_str())
                    .is_none_or(|field| *field != decision.field)
            }) {
                return Err(policy_error());
            }
            if decision.active_binding_sha256 == recovery_binding(&target, &decision.field)? {
                resolved.push(Decisions {
                    schema_version: 1,
                    key_epoch: epoch,
                    field: decision.field.clone(),
                    candidate_ids: decision.candidate_ids.clone(),
                });
            }
        }
        let source = aw_models::SyncPolicyRecoverySourceV1 {
            schema_version: 1,
            vault_id: URL_SAFE_NO_PAD.encode(vault),
            key_epoch: epoch.to_string(),
            snapshot_id: URL_SAFE_NO_PAD.encode(snapshot),
        };
        for active in &policy.active_values {
            let entry = aw_models::SyncRecoveryPolicyCandidateV1 {
                schema_version: 1,
                source: source.clone(),
                field: active.field.clone(),
                value: active.value.clone(),
            };
            candidates.push(recovery_candidate(&entry)?);
            entries.push(entry);
        }
    }
    if candidates.len() > MAX_CURRENT {
        return Err(policy_error());
    }
    let mut unique = std::collections::BTreeSet::new();
    if candidates
        .iter()
        .any(|candidate| !unique.insert(candidate.meta.candidate_id.clone()))
    {
        return Err(policy_error());
    }
    let mut fields = std::collections::BTreeSet::new();
    for candidate in candidates {
        let local = target_hashes
            .get(candidate.meta.field.as_str())
            .ok_or_else(policy_error)?;
        if &candidate.value_sha256 != local
            && !resolved.iter().any(|decision| {
                decision.field == candidate.meta.field
                    && decision
                        .candidate_ids
                        .binary_search(&candidate.meta.candidate_id)
                        .is_ok()
            })
        {
            fields.insert(candidate.meta.field);
        }
    }
    Ok(RecoveryPlan {
        summary: aw_models::SyncRecoveryPolicySummaryV1 {
            schema_version: 1,
            continuity_present: state.policy.is_some(),
            conflict_count: fields.len(),
            target_binding_sha256: hash(&("recovery-target", target))?,
        },
        entries,
        decisions: resolved,
    })
}
pub(crate) fn recovery_summary(
    ds: &DatastoreInstance,
    conn: &Connection,
    state: &crate::SyncRecoveryStateV1,
    vault: [u8; 16],
    epoch: u64,
    snapshot: [u8; 16],
    reset_privacy: bool,
) -> Result<aw_models::SyncRecoveryPolicySummaryV1, DatastoreError> {
    Ok(recovery_plan(ds, conn, state, vault, epoch, snapshot, reset_privacy)?.summary)
}
pub(crate) fn stage_recovery(
    ds: &DatastoreInstance,
    conn: &Connection,
    state: &crate::SyncRecoveryStateV1,
    material: &crate::SyncKeyMaterial,
    snapshot: &crate::SyncSnapshotV1,
) -> Result<(), DatastoreError> {
    let plan = recovery_plan(
        ds,
        conn,
        state,
        *material.vault_id(),
        material.key_epoch(),
        snapshot.snapshot_id,
        false,
    )?;
    conn.execute(
        "DELETE FROM key_value WHERE key GLOB ?1",
        [format!("{DECISION_PREFIX}*")],
    )
    .map_err(|_| policy_error())?;
    for entry in plan.entries {
        let key = recovery_key(&entry.source, &entry.field);
        let raw = serde_json::to_string(&entry).map_err(|_| policy_error())?;
        if raw_key(ds, conn, &key)?.is_some_and(|existing| existing != raw) {
            return Err(policy_error());
        }
        ds.insert_key_value(conn, &key, &raw)?;
    }
    for decision in plan.decisions {
        ds.insert_key_value(
            conn,
            &decision_key(&decision.field),
            &serde_json::to_string(&decision).map_err(|_| policy_error())?,
        )?;
    }
    Ok(())
}

pub(crate) fn export_recovery_policy(
    ds: &DatastoreInstance,
    conn: &Connection,
    history_complete: bool,
) -> Result<aw_models::SyncRecoveryPolicyV1, DatastoreError> {
    let active_values = projected_target(ds, conn, false)?;
    let material = ds.get_sync_key_material(conn)?.ok_or_else(policy_error)?;
    let pending_recovery = recovery_entries(conn)?
        .into_iter()
        .filter(|entry| {
            entry.source.vault_id == URL_SAFE_NO_PAD.encode(material.vault_id())
                && entry.source.key_epoch == material.key_epoch().to_string()
        })
        .collect();
    let mut reviewed = Vec::new();
    if history_complete && ds.get_sync_device_identity(conn)?.is_some() {
        let state = current(ds, conn)?;
        for entry in &active_values {
            let kept = decisions(ds, conn, &entry.field, state.epoch)?;
            let candidate_ids = state
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate.meta.field == entry.field
                        && is_remote(candidate, &state)
                        && kept.contains(&candidate.meta.candidate_id)
                })
                .map(|candidate| candidate.meta.candidate_id.clone())
                .collect::<Vec<_>>();
            if !candidate_ids.is_empty() {
                reviewed.push(aw_models::SyncRecoveryPolicyDecisionV1 {
                    field: entry.field.clone(),
                    candidate_ids,
                    active_binding_sha256: recovery_binding(&active_values, &entry.field)?,
                });
            }
        }
    }
    let policy = aw_models::SyncRecoveryPolicyV1 {
        schema_version: 1,
        active_values,
        decisions: reviewed,
        pending_recovery,
    };
    validate_sync_recovery_policy_v1(&policy)?;
    Ok(policy)
}

pub fn validate_sync_recovery_policy_v1(
    policy: &aw_models::SyncRecoveryPolicyV1,
) -> Result<(), DatastoreError> {
    if policy.schema_version != 1
        || policy.active_values.len() != 21
        || policy.decisions.len() > 21
        || policy
            .active_values
            .windows(2)
            .any(|pair| pair[0].field >= pair[1].field)
        || policy
            .decisions
            .windows(2)
            .any(|pair| pair[0].field >= pair[1].field)
    {
        return Err(policy_error());
    }
    for entry in &policy.active_values {
        validate_sync_policy_field_v1(&entry.field, &entry.value).map_err(|_| policy_error())?;
    }
    for decision in &policy.decisions {
        if !is_sync_policy_field_v1(&decision.field)
            || decision.candidate_ids.is_empty()
            || decision.candidate_ids.len() > MAX_CURRENT
            || decision
                .candidate_ids
                .iter()
                .any(|id| !aw_models::valid_lower_hex(id, 64))
            || decision
                .candidate_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || decision.active_binding_sha256
                != recovery_binding(&policy.active_values, &decision.field)?
        {
            return Err(policy_error());
        }
        aw_models::serialized_size(decision, aw_models::SYNC_MAX_CHUNK_BYTES)
            .map_err(|_| policy_error())?;
    }
    let mut ids = std::collections::BTreeSet::new();
    if policy.pending_recovery.len() > MAX_CURRENT {
        return Err(policy_error());
    }
    for entry in &policy.pending_recovery {
        validate_recovery_entry(entry)?;
        if !ids.insert(recovery_candidate(entry)?.meta.candidate_id) {
            return Err(policy_error());
        }
    }
    Ok(())
}

fn record(
    ds: &DatastoreInstance,
    conn: &Connection,
    field: &str,
    value: SyncPolicyValueV1,
) -> Result<(), DatastoreError> {
    validate_sync_policy_field_v1(field, &value).map_err(|_| policy_error())?;
    let (device, epoch) = ds.local_sync_writer(conn)?;
    let counter = ds.next_sync_operation_counter(conn, &device)?;
    let operation = aw_sync_e2ee::create_policy_change(
        device,
        counter,
        counter,
        BTreeMap::from([(
            field.to_owned(),
            serde_json::to_value(value).map_err(|_| policy_error())?,
        )]),
    )
    .map_err(|_| policy_error())?;
    let identity = ds
        .get_sync_device_identity(conn)?
        .ok_or_else(policy_error)?;
    let material = ds.get_sync_key_material(conn)?.ok_or_else(policy_error)?;
    let signer = aw_sync_e2ee::DeviceIdentityV1::from_bytes(
        device,
        zeroize::Zeroizing::new(*identity.private_key()),
        zeroize::Zeroizing::new(*identity.signing_seed()),
    );
    let manifest = aw_sync_e2ee::SyncManifestV1::new_signed(
        &signer,
        *material.vault_id(),
        epoch,
        1,
        [0; 32],
        vec![operation.clone()],
    )
    .map_err(|_| policy_error())?;
    aw_models::serialized_size(&manifest, aw_models::SYNC_MAX_CHUNK_BYTES)
        .map_err(|_| policy_error())?;
    ds.store_local_sync_operation(conn, device, epoch, &operation)
}

pub const PORTABLE_SETTING_KEYS_V1: [&str; 18] = [
    "settings.startOfDay",
    "settings.startOfWeek",
    "settings.durationDefault",
    "settings.useColorFallback",
    "settings.landingpage",
    "settings.theme",
    "settings.always_active_pattern",
    "settings.privacy_filters",
    "settings.classes",
    "settings.category_sets",
    "settings.active_set_ids",
    "settings.views",
    "settings.saved_queries",
    "settings.ignoredCategorySuggestions",
    "settings.showYearly",
    "settings.useMultidevice",
    "settings.rawRetentionDays",
    "settings.uncategorizedNotificationData",
];

pub fn is_sync_policy_field_v1(field: &str) -> bool {
    PORTABLE_SETTING_KEYS_V1.contains(&field)
        || matches!(
            field,
            "capture.minimization" | "egress.user_policy" | "egress.signed_bundle"
        )
}

pub fn validate_sync_policy_field_v1(
    field: &str,
    portable: &SyncPolicyValueV1,
) -> Result<(), Error> {
    if !is_sync_policy_field_v1(field) {
        return Err(Error::Invalid);
    }
    portable.validate()?;
    if !portable.present {
        return Ok(());
    }
    let value = &portable.value;
    let valid = match field {
        "settings.startOfDay" => value.as_str().is_some_and(|s| {
            let b = s.as_bytes();
            b.len() == 5
                && b[2] == b':'
                && [b[0], b[1], b[3], b[4]].iter().all(u8::is_ascii_digit)
                && (b[0] - b'0') * 10 + b[1] - b'0' < 24
                && (b[3] - b'0') * 10 + b[4] - b'0' < 60
        }),
        "settings.startOfWeek" => matches!(value.as_str(), Some("Saturday" | "Sunday" | "Monday")),
        "settings.durationDefault" => value
            .as_f64()
            .or_else(|| value.as_str()?.trim().parse().ok())
            .is_some_and(|n: f64| n.is_finite() && n > 0.0),
        "settings.useColorFallback" | "settings.showYearly" | "settings.useMultidevice" => {
            value.is_boolean()
        }
        "settings.landingpage" => value.as_str().is_some_and(|s| {
            s.starts_with('/') && !s.starts_with("//") && !s.chars().any(char::is_control)
        }),
        "settings.theme" => matches!(value.as_str(), Some("auto" | "light" | "dark")),
        "settings.always_active_pattern" => value.is_string(),
        "settings.classes" => value.is_null() || categories(value),
        "settings.category_sets" => {
            value.is_null()
                || value.as_array().is_some_and(|sets| {
                    sets.iter().all(|s| {
                        s.as_object().is_some_and(|s| {
                            s.get("id").is_some_and(Value::is_string)
                                && s.get("categories").is_some_and(categories)
                        })
                    })
                })
        }
        "settings.active_set_ids" => value.is_null() || strings(value),
        "settings.ignoredCategorySuggestions" => strings(value),
        "settings.rawRetentionDays" => value.as_u64().is_some_and(|n| n <= 3650),
        "settings.uncategorizedNotificationData" => notification(value),
        "settings.views" => views(value),
        "settings.saved_queries" => saved_queries(value),
        "settings.privacy_filters" => {
            crate::privacy_filter::PrivacyFilterEngine::from_json(&value.to_string()).is_ok()
        }
        "capture.minimization" => {
            value.is_object()
                && serde_json::from_value::<SyncCapturePreferencesV1>(value.clone()).is_ok_and(
                    |preferences| preferences.apply_to(&CapturePolicy::default()).is_ok(),
                )
        }
        "egress.user_policy" => {
            value.is_object()
                && serde_json::from_value::<EgressUserPolicyV1>(value.clone())
                    .is_ok_and(|p| p.validate().is_ok())
        }
        "egress.signed_bundle" => {
            value.is_object()
                && value.get("bundle").is_some_and(Value::is_object)
                && serde_json::from_value::<SignedEgressPolicyBundleV1>(value.clone()).is_ok_and(
                    |p| {
                        p.schema_version == 1
                            && !p.signer_key_id.is_empty()
                            && !p.signer_key_id.chars().any(char::is_control)
                            && p.signature.len() == 64
                            && p.bundle.validate().is_ok()
                    },
                )
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

fn strings(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

fn categories(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        items.iter().all(|category| {
            let Some(category) = category.as_object() else {
                return false;
            };
            let Some(rule) = category.get("rule").and_then(Value::as_object) else {
                return false;
            };
            if !category.get("name").is_some_and(strings)
                || category
                    .get("data")
                    .is_some_and(|data| !data.is_null() && !data.is_object())
            {
                return false;
            }
            match rule.get("type") {
                None | Some(Value::Null) => true,
                Some(Value::String(kind)) if kind == "none" => true,
                Some(Value::String(kind)) if kind == "regex" => {
                    rule.get("regex").is_some_and(Value::is_string)
                        && rule.get("ignore_case").is_none_or(Value::is_boolean)
                        && rule.get("select_keys").is_none_or(|keys| {
                            strings(keys) && keys.as_array().is_some_and(|keys| !keys.is_empty())
                        })
                }
                _ => false,
            }
        })
    })
}

fn object_fields<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Option<&'a Map<String, Value>> {
    let object = value.as_object()?;
    (required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())))
    .then_some(object)
}

fn notification(value: &Value) -> bool {
    object_fields(value, &["isEnabled", "minTotalSeconds", "minRatio"], &[]).is_some_and(|p| {
        p["isEnabled"].is_boolean()
            && p["minTotalSeconds"]
                .as_f64()
                .is_some_and(|n| n.is_finite() && n >= 0.0)
            && p["minRatio"]
                .as_f64()
                .is_some_and(|n| n.is_finite() && (0.0..=1.0).contains(&n))
    })
}

fn saved_queries(value: &Value) -> bool {
    const OFFSETS: [&str; 4] = [
        "start_day_offset",
        "end_day_offset",
        "start_offset",
        "end_offset",
    ];
    value.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            object_fields(
                item,
                &["id", "name", "query_code"],
                &[
                    "start_day_offset",
                    "end_day_offset",
                    "start_offset",
                    "end_offset",
                    "event_type",
                ],
            )
            .is_some_and(|q| {
                ["id", "name", "query_code"]
                    .iter()
                    .all(|key| q[*key].is_string())
                    && OFFSETS.iter().all(|key| {
                        q.get(*key)
                            .is_none_or(|v| v.as_f64().is_some_and(f64::is_finite))
                    })
                    && q.get("event_type").is_none_or(Value::is_string)
            })
        })
    })
}

fn views(value: &Value) -> bool {
    const TYPES: [&str; 17] = [
        "top_apps",
        "top_titles",
        "top_domains",
        "top_urls",
        "top_browser_titles",
        "top_editor_files",
        "top_editor_languages",
        "top_editor_projects",
        "top_categories",
        "category_tree",
        "category_sunburst",
        "timeline_barchart",
        "sunburst_clock",
        "vis_timeline",
        "custom_vis",
        "score",
        "top_stopwatches",
    ];
    value.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            object_fields(item, &["id", "name", "elements"], &[]).is_some_and(|view| {
                view["id"].is_string()
                    && view["name"].is_string()
                    && view["elements"].as_array().is_some_and(|elements| {
                        elements.iter().all(|element| {
                            object_fields(element, &["type"], &["size", "props"]).is_some_and(
                                |element| {
                                    element["type"].as_str().is_some_and(|kind| {
                                        TYPES.contains(&kind) || kind == "top_bucket_data"
                                    }) && element
                                        .get("size")
                                        .is_none_or(|v| v.as_f64().is_some_and(f64::is_finite))
                                        && element.get("props").is_none_or(Value::is_object)
                                },
                            )
                        })
                    })
            })
        })
    })
}
