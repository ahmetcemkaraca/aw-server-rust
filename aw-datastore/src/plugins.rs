//! Encrypted installed-package state and atomic, one-time annotation approvals.
use aw_models::{PluginManifestV1, PluginStorageIntentV1, PluginWriteIntentV1, SignedPluginPackageV1,
    PluginUIOutputV1, EgressPreviewV1, AIUserRequestV1, PluginDestructiveIntentV1, PluginDestructiveActionV1,
    plugin_destructive_target_allowed_v1, plugin_network_resource_index_v1};
use chrono::{Duration, Utc};
use ring::digest::{digest, SHA256};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use crate::{DatastoreError, DatastoreInstance};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstalledPluginV1 {
    pub manifest: PluginManifestV1,
    pub module_sha256: String,
    pub package_sha256: String,
    pub enabled: bool,
    pub revoked: bool,
    pub consent_required: bool,
    pub installed_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub last_background_run_at: Option<String>,
}

impl InstalledPluginV1 {
    pub fn background_due(&self, now: chrono::DateTime<Utc>) -> bool {
        if !self.enabled || self.revoked || self.consent_required { return false; }
        let Some(grant) = &self.manifest.capabilities.background else { return false; };
        match &self.last_background_run_at {
            None => true,
            Some(last) => chrono::DateTime::parse_from_rfc3339(last).is_ok_and(|last|
                now.signed_duration_since(last).num_seconds() >= i64::from(grant.minimum_interval_seconds)),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PluginActionInputsV1 {
    pub ui: Vec<PluginUIOutputV1>,
    pub writes: Vec<PluginWriteIntentV1>,
    pub storage: Vec<PluginStorageIntentV1>,
    pub network_previews: Vec<EgressPreviewV1>,
    pub ai_requests: Vec<AIUserRequestV1>,
    pub destructive_confirmations: Vec<PluginDestructiveIntentV1>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginActionPreviewV1 {
    pub action: PluginDestructiveActionV1,
    pub resource_id: String,
    pub snapshot_sha256: String,
    pub storage_keys: usize,
    pub event_count: usize,
    pub payload_bytes: usize,
    pub approved: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginInvocationPreviewV1 {
    pub schema_version: u16,
    pub invocation_id: String,
    pub package_sha256: String,
    pub ui: Vec<PluginUIOutputV1>,
    pub writes: Vec<PluginWriteIntentV1>,
    pub writes_approved: bool,
    pub network_previews: Vec<EgressPreviewV1>,
    pub ai_requests: Vec<AIUserRequestV1>,
    pub destructive_confirmations: Vec<PluginActionPreviewV1>,
    pub expires_at: String,
    pub background: bool,
}
impl PluginInvocationPreviewV1 {
    /// Send actions release their opaque Firewall token only after host confirmation.
    pub fn for_review(mut self) -> Self {
        for action in &self.destructive_confirmations {
            if action.action == PluginDestructiveActionV1::Send && !action.approved {
                if let Some(index) = plugin_network_resource_index_v1(&action.resource_id) {
                    if let Some(preview) = self.network_previews.get_mut(index) { preview.decision.preview_id.clear(); }
                }
            }
        }
        self
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredPluginV1 {
    pub installed: InstalledPluginV1,
    pub package: SignedPluginPackageV1,
    pub module_bytes: Vec<u8>,
}
impl std::fmt::Debug for StoredPluginV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("StoredPluginV1(<package>)") }
}

#[derive(Clone)]
pub enum PluginOperationV1 {
    List,
    Get(String),
    Install { package: SignedPluginPackageV1, module_bytes: Vec<u8>, expected: Option<String> },
    Consent { plugin_id: String, expected: String },
    Revoke { plugin_id: String, expected: String },
    Delete { plugin_id: String, expected: String },
    PrepareWrites { plugin_id: String, expected: String, invocation_id: String, writes: Vec<PluginWriteIntentV1>, storage: Vec<PluginStorageIntentV1> },
    ApproveWrites { plugin_id: String, expected: String, invocation_id: String },
    History(String),
    PrepareInvocation { plugin_id: String, expected: String, invocation_id: String, actions: PluginActionInputsV1, background: bool },
    Pending(String),
    ApproveAction { plugin_id: String, expected: String, invocation_id: String, action_index: usize },
    BeginBackground { plugin_id: String, expected: String, now: chrono::DateTime<Utc> },
    BackgroundFailed { plugin_id: String, expected: String },
}
impl std::fmt::Debug for PluginOperationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("PluginOperationV1(<private>)") }
}
#[derive(Debug)]
pub enum PluginResultV1 {
    List(Vec<InstalledPluginV1>),
    Stored(Option<StoredPluginV1>),
    Installed(InstalledPluginV1),
    Prepared(String),
    History(Vec<PluginAccessV1>),
    Empty,
    Preview(PluginInvocationPreviewV1),
    Pending(Vec<PluginInvocationPreviewV1>),
    Action(serde_json::Value),
    Due(bool),
}
#[derive(Debug, Serialize)]
pub struct PluginAccessV1 { pub action: String, pub package_sha256: String, pub at: String }

pub fn plugin_package_hash(package: &SignedPluginPackageV1) -> Result<String, DatastoreError> {
    let value = serde_json::to_value(package).map_err(|_| invalid())?;
    let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?;
    Ok(digest(&SHA256, &bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect())
}
fn invalid() -> DatastoreError { DatastoreError::InternalError("Plugin state unavailable or changed; reload and review again".into()) }
fn sql(_: rusqlite::Error) -> DatastoreError { invalid() }
fn encode<T: Serialize>(value: &T) -> Result<String, DatastoreError> { serde_json::to_string(value).map_err(|_| invalid()) }
fn load(conn: &Connection, id: &str) -> Result<Option<StoredPluginV1>, DatastoreError> {
    let row: Option<(String, String, Vec<u8>)> = conn.query_row(
        "SELECT state_json,package_json,module FROM installed_plugins WHERE plugin_id=?1", [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional().map_err(sql)?;
    row.map(|(state, package, module_bytes)| Ok(StoredPluginV1 {
        installed: serde_json::from_str(&state).map_err(|_| invalid())?,
        package: serde_json::from_str(&package).map_err(|_| invalid())?, module_bytes,
    })).transpose()
}
fn checked(conn: &Connection, id: &str, expected: &str, enabled: bool) -> Result<StoredPluginV1, DatastoreError> {
    let stored = load(conn, id)?.ok_or_else(invalid)?;
    if stored.installed.package_sha256 != expected || (enabled && (!stored.installed.enabled || stored.installed.revoked)) { return Err(invalid()); }
    Ok(stored)
}
fn save_state(conn: &Connection, installed: &InstalledPluginV1) -> Result<(), DatastoreError> {
    conn.execute("UPDATE installed_plugins SET state_json=?2 WHERE plugin_id=?1", params![installed.manifest.plugin_id, encode(installed)?]).map_err(sql)?;
    Ok(())
}
fn history(conn: &Connection, id: &str, hash: &str, action: &str) -> Result<(), DatastoreError> {
    conn.execute("INSERT INTO plugin_access(plugin_id,package_sha256,action,at) VALUES (?1,?2,?3,?4)", params![id,hash,action,Utc::now().to_rfc3339()]).map_err(sql)?;
    conn.execute("DELETE FROM plugin_access WHERE plugin_id=?1 AND id NOT IN (SELECT id FROM plugin_access WHERE plugin_id=?1 ORDER BY id DESC LIMIT 100)", [id]).map_err(sql)?;
    Ok(())
}

fn pending_invocation(conn: &Connection, id: &str, hash: &str, invocation: &str) -> Result<PluginInvocationPreviewV1, DatastoreError> {
    let encoded: String = conn.query_row("SELECT prepared_json FROM plugin_pending_invocations WHERE invocation_id=?1 AND plugin_id=?2 AND package_sha256=?3 AND expires_at>?4",
        params![invocation,id,hash,Utc::now().timestamp()],|r|r.get(0)).map_err(sql)?;
    serde_json::from_str(&encoded).map_err(|_|invalid())
}
fn save_pending(conn: &Connection, preview: &PluginInvocationPreviewV1) -> Result<(), DatastoreError> {
    if !preview.background && (preview.writes.is_empty() || preview.writes_approved) && preview.destructive_confirmations.iter().all(|a|a.approved) {
        conn.execute("DELETE FROM plugin_pending_invocations WHERE invocation_id=?1",[&preview.invocation_id]).map_err(sql)?;
    } else {
        conn.execute("UPDATE plugin_pending_invocations SET prepared_json=?2 WHERE invocation_id=?1",params![preview.invocation_id,encode(preview)?]).map_err(sql)?;
    }
    Ok(())
}
fn plugin_snapshot(ds: &DatastoreInstance, conn: &Connection, manifest: &PluginManifestV1) -> Result<(serde_json::Value,String,usize), DatastoreError> {
    let mut stmt = conn.prepare("SELECT storage_key,value_json FROM plugin_storage WHERE publisher_key_id=?1 AND plugin_id=?2 ORDER BY storage_key").map_err(sql)?;
    let rows = stmt.query_map(params![manifest.publisher_key_id,manifest.plugin_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).map_err(sql)?;
    let mut storage = std::collections::BTreeMap::new();
    for row in rows { let (key,value)=row.map_err(sql)?; storage.insert(key,serde_json::from_str::<serde_json::Value>(&value).map_err(|_|invalid())?); }
    let data=serde_json::json!({"storage":storage,"events":ds.get_plugin_events(conn,manifest)?});
    let encoded=serde_json::to_vec(&data).map_err(|_|invalid())?;
    // Metadata overhead exceeds payload quota; keep the host export itself bounded.
    if encoded.len()>8*1024*1024 { return Err(invalid()); }
    let hash=digest(&SHA256,&encoded).as_ref().iter().map(|b|format!("{b:02x}")).collect();
    Ok((data,hash,encoded.len()))
}

impl DatastoreInstance {
    pub(crate) fn plugin_operation(&self, conn: &Connection, operation: PluginOperationV1) -> Result<PluginResultV1, DatastoreError> {
        // The worker checks SQLCipher and runs each operation inside one savepoint.
        use PluginOperationV1::*;
        match operation {
            List => {
                let mut stmt = conn.prepare("SELECT state_json FROM installed_plugins ORDER BY plugin_id").map_err(sql)?;
                let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(sql)?;
                let items = rows.map(|r| serde_json::from_str(&r.map_err(sql)?).map_err(|_| invalid())).collect::<Result<Vec<_>, _>>()?;
                Ok(PluginResultV1::List(items))
            }
            Get(id) => Ok(PluginResultV1::Stored(load(conn, &id)?)),
            Install { package, module_bytes, expected } => {
                package.validate().map_err(|_| invalid())?;
                if module_bytes.is_empty() || module_bytes.len() > 16 * 1024 * 1024 { return Err(invalid()); }
                let hash = plugin_package_hash(&package)?;
                let module_hash: String = digest(&SHA256, &module_bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect();
                if module_hash != package.module_sha256 { return Err(invalid()); }
                let revoked: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM plugin_local_revocations WHERE package_sha256=?1)", [&hash], |r| r.get(0)).map_err(sql)?;
                if revoked { return Err(invalid()); }
                let old = load(conn, &package.manifest.plugin_id)?;
                if old.as_ref().map(|p| &p.installed.package_sha256) != expected.as_ref()
                    || old.as_ref().is_some_and(|p| p.installed.manifest.publisher_key_id != package.manifest.publisher_key_id) { return Err(invalid()); }
                let count: i64 = conn.query_row("SELECT COUNT(*) FROM installed_plugins", [], |r| r.get(0)).map_err(sql)?;
                if old.is_none() && count >= 32 { return Err(invalid()); }
                let now = Utc::now().to_rfc3339();
                let installed = InstalledPluginV1 {
                    manifest: package.manifest.clone(), module_sha256: package.module_sha256.clone(), package_sha256: hash,
                    enabled: false, revoked: false, consent_required: true,
                    installed_at: old.as_ref().map(|p| p.installed.installed_at.clone()).unwrap_or_else(|| now.clone()), updated_at: now,
                    last_background_run_at: None,
                };
                conn.execute("INSERT INTO installed_plugins(plugin_id,state_json,package_json,module) VALUES (?1,?2,?3,?4) ON CONFLICT(plugin_id) DO UPDATE SET state_json=excluded.state_json,package_json=excluded.package_json,module=excluded.module",
                    params![installed.manifest.plugin_id, encode(&installed)?, encode(&package)?, module_bytes]).map_err(sql)?;
                conn.execute("DELETE FROM plugin_pending_invocations WHERE plugin_id=?1", [&installed.manifest.plugin_id]).map_err(sql)?;
                history(conn, &installed.manifest.plugin_id, &installed.package_sha256, if old.is_some() { "updated" } else { "installed" })?;
                Ok(PluginResultV1::Installed(installed))
            }
            Consent { plugin_id, expected } => {
                let mut stored = checked(conn, &plugin_id, &expected, false)?;
                if stored.installed.revoked { return Err(invalid()); }
                stored.installed.enabled = true;
                stored.installed.consent_required = false;
                stored.installed.updated_at = Utc::now().to_rfc3339();
                save_state(conn, &stored.installed)?;
                history(conn, &plugin_id, &expected, "consented")?;
                Ok(PluginResultV1::Installed(stored.installed))
            }
            Revoke { plugin_id, expected } => {
                let mut stored = checked(conn, &plugin_id, &expected, false)?;
                stored.installed.enabled = false;
                stored.installed.revoked = true;
                stored.installed.consent_required = true;
                stored.installed.updated_at = Utc::now().to_rfc3339();
                save_state(conn, &stored.installed)?;
                conn.execute("INSERT OR IGNORE INTO plugin_local_revocations(package_sha256) VALUES (?1)", [&expected]).map_err(sql)?;
                conn.execute("DELETE FROM plugin_pending_invocations WHERE plugin_id=?1", [&plugin_id]).map_err(sql)?;
                history(conn, &plugin_id, &expected, "revoked")?;
                Ok(PluginResultV1::Installed(stored.installed))
            }
            Delete { plugin_id, expected } => {
                let stored = checked(conn, &plugin_id, &expected, false)?;
                self.delete_plugin_data(conn, &stored.installed.manifest)?;
                for table in ["installed_plugins", "plugin_pending_invocations", "plugin_access"] {
                    conn.execute(&format!("DELETE FROM {table} WHERE plugin_id=?1"), [&plugin_id]).map_err(sql)?;
                }
                Ok(PluginResultV1::Empty)
            }
            PrepareWrites { plugin_id, expected, invocation_id, writes, storage } => {
                let result = self.plugin_operation(conn, PrepareInvocation { plugin_id, expected, invocation_id,
                    actions: PluginActionInputsV1 { writes, storage, ..Default::default() }, background: false })?;
                let PluginResultV1::Preview(preview) = result else { return Err(invalid()); };
                Ok(PluginResultV1::Prepared(preview.expires_at))
            }
            PrepareInvocation { plugin_id, expected, invocation_id, actions, background } => {
                let stored = checked(conn, &plugin_id, &expected, true)?;
                aw_models::validate_plugin_output_v1(&stored.installed.manifest, aw_models::PluginInvocationOutputV1 {
                    schema_version: 1, ui: actions.ui.clone(), writes: actions.writes.clone(), network: vec![], ai: vec![], storage: actions.storage.clone(), destructive: vec![],
                }, None).map_err(|_| invalid())?;
                if actions.destructive_confirmations.len() > 32 || actions.network_previews.len() > 32 || actions.ai_requests.len() > 32
                    || actions.ai_requests.iter().any(|request| request.validate().is_err())
                    || actions.destructive_confirmations.iter().any(|intent|
                        !plugin_destructive_target_allowed_v1(intent, actions.network_previews.len())
                        || !stored.installed.manifest.capabilities.destructive.iter().any(|grant| grant.action == intent.action && grant.confirmation_required)) {
                    return Err(invalid());
                }
                let now = Utc::now();
                conn.execute("DELETE FROM plugin_pending_invocations WHERE expires_at<=?1", [now.timestamp()]).map_err(sql)?;
                let pending = !actions.writes.is_empty() || !actions.destructive_confirmations.is_empty()
                    || (background && (!actions.ui.is_empty() || !actions.network_previews.is_empty() || !actions.ai_requests.is_empty()));
                if pending {
                    let count: i64 = conn.query_row("SELECT COUNT(*) FROM plugin_pending_invocations", [], |r| r.get(0)).map_err(sql)?;
                    if count >= 32 || invocation_id.len() != 36 { return Err(invalid()); }
                }
                if !actions.storage.is_empty() { self.apply_plugin_storage_intents(conn, &stored.installed.manifest, &actions.storage)?; }
                let mut confirmations = Vec::new();
                for intent in actions.destructive_confirmations {
                    let mut preview = PluginActionPreviewV1 { action: intent.action, resource_id: intent.resource_id,
                        snapshot_sha256: String::new(), storage_keys: 0, event_count: 0, payload_bytes: 0, approved: false };
                    if preview.action != PluginDestructiveActionV1::Send {
                        let (data, hash, bytes) = plugin_snapshot(self, conn, &stored.installed.manifest)?;
                        preview.snapshot_sha256 = hash;
                        preview.storage_keys = data["storage"].as_object().ok_or_else(invalid)?.len();
                        preview.event_count = data["events"].as_array().ok_or_else(invalid)?.len();
                        preview.payload_bytes = bytes;
                    }
                    confirmations.push(preview);
                }
                let expiry = now + Duration::minutes(5);
                let preview = PluginInvocationPreviewV1 { schema_version: 1, invocation_id, package_sha256: expected.clone(),
                    ui: actions.ui, writes: actions.writes, writes_approved: false, network_previews: actions.network_previews,
                    ai_requests: actions.ai_requests, destructive_confirmations: confirmations, expires_at: expiry.to_rfc3339(), background };
                let encoded = encode(&preview)?;
                if encoded.len() > 2 * 1024 * 1024 { return Err(invalid()); }
                if pending {
                    conn.execute("INSERT INTO plugin_pending_invocations(invocation_id,plugin_id,package_sha256,prepared_json,expires_at) VALUES (?1,?2,?3,?4,?5)",
                        params![preview.invocation_id, plugin_id, expected, encoded, expiry.timestamp()]).map_err(sql)?;
                }
                history(conn, &plugin_id, &expected, if background { "background_invoked" } else { "invoked" })?;
                Ok(PluginResultV1::Preview(preview.for_review()))
            }
            ApproveWrites { plugin_id, expected, invocation_id } => {
                let stored = checked(conn, &plugin_id, &expected, true)?;
                let mut preview = pending_invocation(conn, &plugin_id, &expected, &invocation_id)?;
                if preview.writes.is_empty() || preview.writes_approved { return Err(invalid()); }
                self.apply_plugin_write_intents(conn, &stored.installed.manifest, &preview.writes)?;
                preview.writes_approved = true;
                save_pending(conn, &preview)?;
                history(conn, &plugin_id, &expected, "writes_approved")?;
                Ok(PluginResultV1::Empty)
            }
            Pending(id) => {
                let mut stmt = conn.prepare("SELECT prepared_json FROM plugin_pending_invocations WHERE plugin_id=?1 AND expires_at>?2 ORDER BY expires_at DESC LIMIT 32").map_err(sql)?;
                let rows = stmt.query_map(params![id,Utc::now().timestamp()], |r| r.get::<_,String>(0)).map_err(sql)?;
                let previews = rows.map(|row| serde_json::from_str::<PluginInvocationPreviewV1>(&row.map_err(sql)?).map(|p|p.for_review()).map_err(|_|invalid())).collect::<Result<Vec<_>,_>>()?;
                Ok(PluginResultV1::Pending(previews))
            }
            ApproveAction { plugin_id, expected, invocation_id, action_index } => {
                let stored = checked(conn, &plugin_id, &expected, true)?;
                let mut preview = pending_invocation(conn, &plugin_id, &expected, &invocation_id)?;
                let action = preview.destructive_confirmations.get_mut(action_index).ok_or_else(invalid)?;
                if action.approved || !stored.installed.manifest.capabilities.destructive.iter().any(|grant| grant.action == action.action && grant.confirmation_required) { return Err(invalid()); }
                let result = match action.action {
                    PluginDestructiveActionV1::Send => {
                        let index = plugin_network_resource_index_v1(&action.resource_id).ok_or_else(invalid)?;
                        let network_preview = preview.network_previews.get(index).ok_or_else(invalid)?;
                        serde_json::json!({"schema_version":1,"action":"send","network_preview":network_preview})
                    }
                    PluginDestructiveActionV1::Delete | PluginDestructiveActionV1::Export => {
                        if action.resource_id != "plugin_owned_data" { return Err(invalid()); }
                        let (data, hash, _) = plugin_snapshot(self, conn, &stored.installed.manifest)?;
                        if hash != action.snapshot_sha256 { return Err(invalid()); }
                        if action.action == PluginDestructiveActionV1::Delete {
                            self.delete_plugin_data(conn, &stored.installed.manifest)?;
                            serde_json::json!({"schema_version":1,"action":"delete","ok":true})
                        } else { serde_json::json!({"schema_version":1,"action":"export","data":data}) }
                    }
                };
                action.approved = true;
                save_pending(conn, &preview)?;
                history(conn, &plugin_id, &expected, "action_approved")?;
                Ok(PluginResultV1::Action(result))
            }
            BeginBackground { plugin_id, expected, now } => {
                let mut stored = checked(conn, &plugin_id, &expected, true)?;
                if !stored.installed.background_due(now) { return Ok(PluginResultV1::Due(false)); }
                stored.installed.last_background_run_at = Some(now.to_rfc3339());
                save_state(conn, &stored.installed)?;
                Ok(PluginResultV1::Due(true))
            }
            BackgroundFailed { plugin_id, expected } => {
                checked(conn, &plugin_id, &expected, false)?;
                history(conn, &plugin_id, &expected, "background_failed")?;
                Ok(PluginResultV1::Empty)
            }
            History(id) => {
                let mut stmt = conn.prepare("SELECT action,package_sha256,at FROM plugin_access WHERE plugin_id=?1 ORDER BY id DESC LIMIT 100").map_err(sql)?;
                let rows = stmt.query_map([id], |r| Ok(PluginAccessV1 { action: r.get(0)?, package_sha256: r.get(1)?, at: r.get(2)? })).map_err(sql)?;
                Ok(PluginResultV1::History(rows.collect::<Result<Vec<_>, _>>().map_err(sql)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_models::{PluginCapabilitiesV1, PluginWriteCapabilityV1};
    #[test]
    fn expired_and_cross_package_write_approvals_fail_without_persisting_events() {
        let conn=Connection::open_in_memory().unwrap();
        let ds=DatastoreInstance::new(&conn,true,false).unwrap();
        let module=vec![0,97,115,109];
        let package=SignedPluginPackageV1 { schema_version:1, manifest:PluginManifestV1 {
            schema_version:1,plugin_id:"test-plugin".into(),version:"1.0.0".into(),publisher_key_id:"test-publisher".into(),display_name:"Test".into(),description:String::new(),
            capabilities:PluginCapabilitiesV1 {write:vec![PluginWriteCapabilityV1 {event_type:"plugin.annotation".into(),schema_id:"annotation-v1".into()}],..Default::default()},
        }, module_sha256:digest(&SHA256,&module).as_ref().iter().map(|b|format!("{b:02x}")).collect(),signature:vec![0;64] };
        let hash=plugin_package_hash(&package).unwrap();let id=package.manifest.plugin_id.clone();
        ds.plugin_operation(&conn,PluginOperationV1::Install {package:package.clone(),module_bytes:module,expected:None}).unwrap();
        ds.plugin_operation(&conn,PluginOperationV1::Consent {plugin_id:id.clone(),expected:hash.clone()}).unwrap();
        let invocation_id="aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa".to_owned();
        ds.plugin_operation(&conn,PluginOperationV1::PrepareWrites {plugin_id:id.clone(),expected:hash.clone(),invocation_id:invocation_id.clone(),storage:vec![],writes:vec![PluginWriteIntentV1 {event_type:"plugin.annotation".into(),schema_id:"annotation-v1".into(),payload:serde_json::json!({"title":"Test","body":"Check"})}]}).unwrap();
        assert!(ds.plugin_operation(&conn,PluginOperationV1::ApproveWrites {plugin_id:id.clone(),expected:"b".repeat(64),invocation_id:invocation_id.clone()}).is_err());
        conn.execute("UPDATE plugin_pending_invocations SET expires_at=0",[]).unwrap();
        assert!(ds.plugin_operation(&conn,PluginOperationV1::ApproveWrites {plugin_id:id.clone(),expected:hash.clone(),invocation_id}).is_err());
        assert!(ds.get_plugin_events(&conn,&package.manifest).unwrap().is_empty());
        for _ in 0..40 {
            ds.plugin_operation(&conn,PluginOperationV1::PrepareWrites {plugin_id:id.clone(),expected:hash.clone(),invocation_id:"unused".into(),writes:vec![],storage:vec![]}).unwrap();
        }
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM plugin_pending_invocations",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        for index in 0..33 {
            let result=ds.plugin_operation(&conn,PluginOperationV1::PrepareWrites {plugin_id:id.clone(),expected:hash.clone(),invocation_id:format!("{index:08x}-aaaa-4aaa-aaaa-aaaaaaaaaaaa"),storage:vec![],writes:vec![PluginWriteIntentV1 {event_type:"plugin.annotation".into(),schema_id:"annotation-v1".into(),payload:serde_json::json!({"title":"Test","body":"Check"})}]});
            assert_eq!(result.is_ok(),index<32);
        }
        let plain=crate::Datastore::new_in_memory(false);
        assert!(plain.plugin_operation(PluginOperationV1::List).is_err());
    }
}
