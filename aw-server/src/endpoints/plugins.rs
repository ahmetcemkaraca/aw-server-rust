use rocket::serde::json::Json;
use rocket::State;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Release integration owns these public keys and review/revocation records.
/// No HTTP endpoint, settings key or plugin package can modify this registry.
#[derive(Clone, Default)]
pub struct PluginTrust {
    keys: HashMap<String, Vec<u8>>,
    reviewed_packages: HashSet<String>,
    revoked_publishers: HashSet<String>,
    revoked_packages: HashSet<String>,
    sandbox_review_digest: Option<String>,
    gate: Arc<Mutex<()>>,
}
impl PluginTrust {
    pub fn from_release_registry(
        keys: HashMap<String, Vec<u8>>, reviewed_packages: HashSet<String>,
        revoked_publishers: HashSet<String>, revoked_packages: HashSet<String>,
        sandbox_review_digest: String,
    ) -> Result<Self, &'static str> {
        let hash = |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if keys.is_empty() || keys.iter().any(|(id, key)| id.is_empty() || key.len() != 32)
            || !hash(&sandbox_review_digest) || reviewed_packages.iter().chain(&revoked_packages).any(|v| !hash(v)) {
            return Err("Invalid release-owned plugin trust registry");
        }
        Ok(Self { keys, reviewed_packages, revoked_publishers, revoked_packages, sandbox_review_digest: Some(sandbox_review_digest), gate: Arc::new(Mutex::new(())) })
    }
    fn ready(&self) -> bool {
        cfg!(all(feature = "plugin-runtime", any(feature = "encryption", feature = "encryption-vendored")))
            && cfg!(all(any(target_os = "linux", target_os = "macos", target_os = "windows"), any(target_arch = "x86_64", target_arch = "aarch64")))
            && !self.keys.is_empty() && !self.reviewed_packages.is_empty() && self.sandbox_review_digest.is_some()
    }
}

#[derive(Serialize)]
pub struct PluginServiceStatusV1 {
    pub schema_version: u16,
    pub runtime_compiled: bool,
    pub runtime_available: bool,
    pub lifecycle_available: bool,
    pub marketplace_available: bool,
    pub signed_purpose_available: bool,
    pub blocker_ids: Vec<&'static str>,
}
#[get("/status")]
pub fn status(trust: &State<PluginTrust>, state: &State<crate::endpoints::ServerState>, config: &State<crate::config::AWConfig>) -> Json<PluginServiceStatusV1> {
    Json(service_status(trust, state.datastore.is_encrypted() && !state.datastore.is_locked() && config.auth.sessions.is_some()))
}
fn service_status(trust: &PluginTrust, vault_available: bool) -> PluginServiceStatusV1 {
    let mut blockers = vec!["marketplace_operations"];
    if trust.sandbox_review_digest.is_none() { blockers.push("sandbox_escape_review"); }
    if trust.keys.is_empty() { blockers.push("publisher_trust_registry"); }
    if trust.reviewed_packages.is_empty() { blockers.push("package_review_and_provenance"); }
    PluginServiceStatusV1 {
        schema_version: 1,
        runtime_compiled: cfg!(feature = "plugin-runtime"),
        runtime_available: trust.ready() && vault_available,
        lifecycle_available: cfg!(all(feature = "plugin-runtime", any(feature = "encryption", feature = "encryption-vendored"))) && vault_available,
        marketplace_available: false,
        signed_purpose_available: false,
        blocker_ids: blockers,
    }
}

#[cfg(all(feature = "plugin-runtime", any(feature = "encryption", feature = "encryption-vendored")))]
pub mod lifecycle {
    use super::*;
    use aw_datastore::{Datastore, plugins::{StoredPluginV1, PluginOperationV1 as Op, PluginResultV1 as ResultV1, plugin_package_hash}};
    use aw_models::{SignedPluginPackageV1, plugin_capability_diff_v1};
    use aw_plugin_runtime::{verify_plugin_package_v1, PluginRuntimeV1, VerifiedPluginPackageV1};
    use aw_egress::EgressProxy;
    use rocket::http::Status;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use chrono::Utc;
    use crate::{config::AWConfig, endpoints::{ServerState, HttpErrorJson, egress::{active_policy, EgressPolicyTrust}}};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PackageRequest {
        package: SignedPluginPackageV1,
        module_bytes: Vec<u8>,
        #[serde(default)] expected_package_sha256: Option<String>,
    }
    // A 16 MiB byte array needs at most 64 MiB of compact JSON plus manifest metadata.
    // Keep this exception local to package uploads instead of raising all API limits.
    pub struct PackageUpload(PackageRequest);
    #[rocket::async_trait]
    impl<'r> rocket::data::FromData<'r> for PackageUpload {
        type Error = &'static str;
        async fn from_data(_: &'r rocket::Request<'_>, data: rocket::Data<'r>) -> rocket::data::Outcome<'r, Self> {
            use rocket::data::ToByteUnit;
            match data.open(65.mebibytes()).into_bytes().await {
                Ok(bytes) if bytes.is_complete() => match serde_json::from_slice(&bytes) {
                    Ok(package) => rocket::data::Outcome::Success(Self(package)),
                    Err(_) => rocket::data::Outcome::Error((Status::UnprocessableEntity, "Invalid plugin package upload")),
                },
                Ok(_) => rocket::data::Outcome::Error((Status::PayloadTooLarge, "Plugin package upload exceeds its bound")),
                Err(_) => rocket::data::Outcome::Error((Status::BadRequest, "Plugin package upload unavailable")),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ConfirmRequest { package_sha256: String, confirmed: bool }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeRequest { package_sha256: String }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ApproveRequest { invocation_id: String, package_sha256: String, confirmed: bool }

    fn error(status: Status, message: &str) -> HttpErrorJson { HttpErrorJson::new(status, message.into()) }
    fn available(store: &Datastore, scoped: bool) -> Result<(), HttpErrorJson> {
        if !scoped { return Err(error(Status::ServiceUnavailable, "Plugins require scoped local sessions")); }
        if store.is_locked() { return Err(error(Status::Locked, "Unlock the encrypted vault to manage plugins")); }
        if !store.is_encrypted() { return Err(error(Status::ServiceUnavailable, "Plugins require an encrypted vault")); }
        Ok(())
    }
    fn operation(store: &Datastore, op: Op) -> Result<ResultV1, HttpErrorJson> {
        store.plugin_operation(op).map_err(|_| error(Status::Conflict, "Plugin state changed or approval expired; reload and review again"))
    }
    fn stored(store: &Datastore, id: &str, hash: Option<&str>) -> Result<StoredPluginV1, HttpErrorJson> {
        match operation(store, Op::Get(id.into()))? {
            ResultV1::Stored(Some(stored)) if hash.is_none_or(|hash| hash == stored.installed.package_sha256) => Ok(stored),
            _ => Err(error(Status::Conflict, "Installed plugin changed or no longer exists")),
        }
    }
    fn verified(trust: &PluginTrust, package: &SignedPluginPackageV1, module: &[u8]) -> Result<VerifiedPluginPackageV1, HttpErrorJson> {
        if !trust.ready() { return Err(error(Status::ServiceUnavailable, "Publisher trust and independent sandbox review are unavailable")); }
        let hash = plugin_package_hash(package).map_err(|_| error(Status::UnprocessableEntity, "Invalid plugin package"))?;
        if !trust.reviewed_packages.contains(&hash) || trust.revoked_packages.contains(&hash) {
            return Err(error(Status::Forbidden, "Package review/provenance is missing or this package was revoked"));
        }
        verify_plugin_package_v1(package, module, &trust.keys, &trust.revoked_publishers, &HashSet::new())
            .map_err(|_| error(Status::Forbidden, "The plugin signature, publisher or module could not be verified"))
    }
    fn response(result: ResultV1) -> Result<Json<Value>, HttpErrorJson> {
        match result {
            ResultV1::Installed(plugin) => Ok(Json(json!(plugin))),
            ResultV1::Empty => Ok(Json(json!({"schema_version":1,"ok":true}))),
            _ => Err(error(Status::ServiceUnavailable, "Plugin operation unavailable")),
        }
    }
    fn confirmed(value: bool) -> Result<(), HttpErrorJson> {
        if value { Ok(()) } else { Err(error(Status::BadRequest, "Explicit confirmation is required")) }
    }
    fn lock(trust: &PluginTrust) -> Result<std::sync::MutexGuard<'_, ()>, HttpErrorJson> {
        // ponytail: serialize plugin calls; use per-plugin gates if contention is measurable.
        trust.gate.lock().map_err(|_| error(Status::ServiceUnavailable, "Plugin service unavailable"))
    }

    #[get("/installed")]
    pub fn installed(state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>) -> Result<Json<Value>, HttpErrorJson> {
        available(&state.datastore, config.auth.sessions.is_some())?;
        let _gate = lock(trust)?;
        let ResultV1::List(mut plugins) = operation(&state.datastore, Op::List)? else { unreachable!() };
        // A release-registry kill/revoke change is also persisted on the next inventory read.
        for plugin in &mut plugins {
            if trust.revoked_packages.contains(&plugin.package_sha256) || trust.revoked_publishers.contains(&plugin.manifest.publisher_key_id) {
                if !plugin.revoked {
                    if let ResultV1::Installed(revoked) = operation(&state.datastore, Op::Revoke { plugin_id: plugin.manifest.plugin_id.clone(), expected: plugin.package_sha256.clone() })? { *plugin = revoked; }
                }
            }
            if !trust.ready() || !trust.reviewed_packages.contains(&plugin.package_sha256) || !trust.keys.contains_key(&plugin.manifest.publisher_key_id) { plugin.enabled = false; }
        }
        Ok(Json(json!({"schema_version":1,"plugins":plugins})))
    }
    fn install_package(request: PackageRequest, id: Option<String>, store: Datastore, scoped: bool, trust: PluginTrust, policy_trust: EgressPolicyTrust, proxy: EgressProxy) -> Result<Json<Value>, HttpErrorJson> {
        available(&store, scoped)?;
        let _gate = lock(&trust)?;
        if id.as_deref().is_some_and(|id| id != request.package.manifest.plugin_id) || id.is_some() != request.expected_package_sha256.is_some() {
            return Err(error(Status::BadRequest, "An update must identify the exact installed package"));
        }
        let package = verified(&trust, &request.package, &request.module_bytes)?;
        if !package.manifest().capabilities.network.is_empty() {
            let policy = active_policy(&store, &policy_trust)?;
            aw_egress::validate_plugin_egress_grants_v1(package.manifest(), &policy).map_err(|_| error(Status::Forbidden, "Plugin network grants do not match signed Egress policy"))?;
        }
        let runtime = PluginRuntimeV1::new().map_err(|_| error(Status::ServiceUnavailable, "Sandbox unavailable"))?;
        runtime.compile_verified(&package).map_err(|_| error(Status::UnprocessableEntity, "Plugin module does not satisfy the sandbox ABI"))?;
        let diff = id.as_ref().map(|id| {
            let previous = stored(&store, id, request.expected_package_sha256.as_deref())?;
            plugin_capability_diff_v1(&previous.installed.manifest.capabilities, &package.manifest().capabilities)
                .map_err(|_| error(Status::UnprocessableEntity, "Invalid plugin permissions"))
        }).transpose()?;
        let result = proxy.with_plugin_change(|| operation(&store, Op::Install {
            package: request.package, module_bytes: request.module_bytes, expected: request.expected_package_sha256,
        })).map_err(|_| error(Status::ServiceUnavailable, "Outbound approvals could not be invalidated"))??;
        match result {
            ResultV1::Installed(plugin) if id.is_some() => Ok(Json(json!({"plugin":plugin,"capability_diff":diff}))),
            other => response(other),
        }
    }
    #[post("/install", data = "<request>", format = "application/json")]
    pub async fn install(request: PackageUpload, state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>, policy: &State<EgressPolicyTrust>, proxy: &State<EgressProxy>) -> Result<Json<Value>, HttpErrorJson> {
        let (store, scoped, trust, policy, proxy) = (state.datastore.clone(), config.auth.sessions.is_some(), trust.inner().clone(), policy.inner().clone(), proxy.inner().clone());
        rocket::tokio::task::spawn_blocking(move || install_package(request.0, None, store, scoped, trust, policy, proxy)).await.map_err(|_| error(Status::ServiceUnavailable, "Plugin installation unavailable"))?
    }
    #[post("/<plugin_id>/update", data = "<request>", format = "application/json")]
    pub async fn update(plugin_id: String, request: PackageUpload, state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>, policy: &State<EgressPolicyTrust>, proxy: &State<EgressProxy>) -> Result<Json<Value>, HttpErrorJson> {
        let (store, scoped, trust, policy, proxy) = (state.datastore.clone(), config.auth.sessions.is_some(), trust.inner().clone(), policy.inner().clone(), proxy.inner().clone());
        rocket::tokio::task::spawn_blocking(move || install_package(request.0, Some(plugin_id), store, scoped, trust, policy, proxy)).await.map_err(|_| error(Status::ServiceUnavailable, "Plugin update unavailable"))?
    }
    #[post("/<plugin_id>/consent", data = "<request>", format = "application/json")]
    pub fn consent(plugin_id: String, request: Json<ConfirmRequest>, state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>) -> Result<Json<Value>, HttpErrorJson> {
        available(&state.datastore, config.auth.sessions.is_some())?; confirmed(request.confirmed)?;
        let _gate = lock(trust)?;
        let plugin = stored(&state.datastore, &plugin_id, Some(&request.package_sha256))?;
        verified(trust, &plugin.package, &plugin.module_bytes)?;
        response(operation(&state.datastore, Op::Consent { plugin_id, expected: request.package_sha256.clone() })?)
    }
    #[post("/<plugin_id>/revoke", data = "<request>", format = "application/json")]
    pub fn revoke(plugin_id: String, request: Json<ConfirmRequest>, state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>, proxy: &State<EgressProxy>) -> Result<Json<Value>, HttpErrorJson> {
        available(&state.datastore, config.auth.sessions.is_some())?; confirmed(request.confirmed)?;
        let _gate = lock(trust)?;
        response(proxy.with_plugin_change(|| operation(&state.datastore, Op::Revoke { plugin_id, expected: request.package_sha256.clone() })).map_err(|_| error(Status::ServiceUnavailable, "Outbound approvals could not be invalidated"))??)
    }
    #[delete("/<plugin_id>", data = "<request>", format = "application/json")]
    pub fn delete(plugin_id: String, request: Json<ConfirmRequest>, state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>, proxy: &State<EgressProxy>) -> Result<Json<Value>, HttpErrorJson> {
        available(&state.datastore, config.auth.sessions.is_some())?; confirmed(request.confirmed)?;
        let _gate = lock(trust)?;
        response(proxy.with_plugin_change(|| operation(&state.datastore, Op::Delete { plugin_id, expected: request.package_sha256.clone() })).map_err(|_| error(Status::ServiceUnavailable, "Outbound approvals could not be invalidated"))??)
    }
    #[post("/<plugin_id>/invoke", data = "<request>", format = "application/json")]
    pub async fn invoke(plugin_id: String, request: Json<InvokeRequest>, state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>, policy: &State<EgressPolicyTrust>, proxy: &State<EgressProxy>) -> Result<Json<Value>, HttpErrorJson> {
        let (store, scoped, trust, policy_trust, proxy) = (state.datastore.clone(), config.auth.sessions.is_some(), trust.inner().clone(), policy.inner().clone(), proxy.inner().clone());
        rocket::tokio::task::spawn_blocking(move || {
            available(&store, scoped)?;
            let _gate = lock(&trust)?;
            let plugin = stored(&store, &plugin_id, Some(&request.package_sha256))?;
            if !plugin.installed.enabled || plugin.installed.revoked { return Err(error(Status::Forbidden, "Plugin is disabled or requires consent")); }
            let package = verified(&trust, &plugin.package, &plugin.module_bytes)?;
            let runtime = PluginRuntimeV1::new().map_err(|_| error(Status::ServiceUnavailable, "Sandbox unavailable"))?;
            let compiled = runtime.compile_verified(&package).map_err(|_| error(Status::UnprocessableEntity, "Invalid plugin module"))?;
            let input = crate::plugin_host::prepare_plugin_input(&store, package.manifest(), Utc::now()).map_err(|_| error(Status::Forbidden, "Plugin input exceeds its grants or limits"))?;
            let settings = store.get_ai_settings().map_err(HttpErrorJson::from)?;
            let active_profile = if settings.mode == aw_models::AIAccessModeV1::CustomEndpoint { settings.active_connection_id.as_deref() } else { None };
            let output = runtime.invoke(&compiled, &input, active_profile).map_err(|_| error(Status::UnprocessableEntity, "Plugin exceeded sandbox limits or returned ungranted effects"))?;
            if !output.as_inner().destructive.is_empty() { return Err(error(Status::ServiceUnavailable, "Generic destructive plugin actions are unavailable; use explicit host controls")); }
            let (ui, writes, storage, network_previews, ai_requests) = if output.as_inner().network.is_empty() && output.as_inner().ai.is_empty() {
                let output = output.into_inner();
                (output.ui, output.writes, output.storage, vec![], vec![])
            } else {
                let policy = active_policy(&store, &policy_trust)?;
                let actions = crate::plugin_host::prepare_plugin_actions(&store, &proxy, &policy, package.manifest(), output, active_profile, Utc::now(), chrono::Local::now().offset().local_minus_utc())
                    .map_err(|_| error(Status::Forbidden, "Plugin actions do not match active Egress or AI policy"))?;
                (actions.ui, actions.writes, actions.storage, actions.network_previews, actions.ai_requests)
            };
            let invocation_id = uuid::Uuid::new_v4().to_string();
            let ResultV1::Prepared(expires_at) = operation(&store, Op::PrepareWrites { plugin_id, expected: request.package_sha256.clone(), invocation_id: invocation_id.clone(), writes: writes.clone(), storage })? else { unreachable!() };
            Ok(Json(json!({"schema_version":1,"invocation_id":invocation_id,"package_sha256":request.package_sha256,"ui":ui,"writes":writes,"network_previews":network_previews,"ai_requests":ai_requests,"destructive_confirmations":[],"expires_at":expires_at})))
        }).await.map_err(|_| error(Status::ServiceUnavailable, "Plugin invocation unavailable"))?
    }
    #[post("/<plugin_id>/writes/approve", data = "<request>", format = "application/json")]
    pub fn approve_writes(plugin_id: String, request: Json<ApproveRequest>, state: &State<ServerState>, config: &State<AWConfig>, trust: &State<PluginTrust>) -> Result<Json<Value>, HttpErrorJson> {
        available(&state.datastore, config.auth.sessions.is_some())?; confirmed(request.confirmed)?;
        let _gate = lock(trust)?;
        let plugin = stored(&state.datastore, &plugin_id, Some(&request.package_sha256))?;
        verified(trust, &plugin.package, &plugin.module_bytes)?;
        response(operation(&state.datastore, Op::ApproveWrites { plugin_id, expected: request.package_sha256.clone(), invocation_id: request.invocation_id.clone() })?)
    }
    #[get("/<plugin_id>/history")]
    pub fn history(plugin_id: String, state: &State<ServerState>, config: &State<AWConfig>) -> Result<Json<Value>, HttpErrorJson> {
        available(&state.datastore, config.auth.sessions.is_some())?;
        let ResultV1::History(history) = operation(&state.datastore, Op::History(plugin_id))? else { unreachable!() };
        Ok(Json(json!({"schema_version":1,"history":history})))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sandbox_execution_and_marketplace_remain_closed_without_host_services() {
        let trust = PluginTrust::default();
        let status = service_status(&trust, true);
        assert_eq!(status.runtime_compiled, cfg!(feature = "plugin-runtime"));
        assert!(!status.runtime_available);
        assert!(!status.marketplace_available);
        assert!(!status.signed_purpose_available);
        assert!(PluginTrust::from_release_registry(HashMap::new(), HashSet::new(), HashSet::new(), HashSet::new(), "invalid".into()).is_err());
    }
}
