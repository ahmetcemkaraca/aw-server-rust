use aw_datastore::{Datastore, DatastoreError};
use aw_egress::{EgressProxy, VerifiedPolicyV1};
use aw_models::{
    AIAccessModeV1, AIEndpointProfileV1, AIRequestFeatureV1, AIRequestPreviewV1,
    AIInsightHistoryV1, AIInsightV1, AIResultV1, AISettingsV1, AIUserRequestV1, EgressApprovalScopeV1,
    EgressApprovalV1, EgressDecisionV1, EgressReasonCodeV1,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{Request, State};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::config::AWConfig;
use crate::endpoints::apikey::AiSendOnly;
use crate::endpoints::egress::{active_policy, EgressPolicyTrust};
use crate::endpoints::{HttpErrorJson, ServerState};

const MAX_RESPONSE_BYTES: usize = 128 * 1024;

fn native_ai_credential(values: &[&str]) -> Result<Option<Zeroizing<String>>, Status> {
    if values.is_empty() { return Ok(None); }
    if values.len() != 1 { return Err(Status::BadRequest); }
    let value = values[0];
    if value.is_empty() || value.len() > 8192 || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(Status::BadRequest);
    }
    Ok(Some(Zeroizing::new(value.to_owned())))
}

struct NativeAICredential(Option<Zeroizing<String>>);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for NativeAICredential {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let values = request.headers().get("X-PeakActivity-AI-Credential").collect::<Vec<_>>();
        match native_ai_credential(&values) {
            Ok(secret) => rocket::request::Outcome::Success(Self(secret)),
            Err(status) => rocket::request::Outcome::Error((status, "Invalid native AI credential header")),
        }
    }
}

#[derive(Serialize)]
pub struct AIServiceStatusV1 {
    schema_version: u16,
    mode: AIAccessModeV1,
    revision: u64,
    peak_ai_available: bool,
    custom_endpoint_available: bool,
    native_secret_store_available: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateAISettingsRequestV1 {
    expected_revision: u64,
    settings: AISettingsV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionTestRequestV1 {
    profile: AIEndpointProfileV1,
}

#[derive(Serialize)]
pub struct ConnectionTestResponseV1 {
    schema_version: u16,
    http_status: u16,
    tls_verified: bool,
    resolved_addresses: Vec<String>,
    disclosure_status: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveAIRequestV1 {
    profile_id: String,
    preview_id: String,
    scope: EgressApprovalScopeV1,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativePreviewRequestV1 {
    approval_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendAIRequestV1 {
    profile_id: String,
    credential_ref: Option<String>,
    preview_id: String,
    approval_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveInsightRequestV1 {
    feature: AIRequestFeatureV1,
    result: AIResultV1,
}

fn require_encrypted(datastore: &Datastore) -> Result<(), HttpErrorJson> {
    if datastore.is_locked() {
        return Err(HttpErrorJson::new(Status::Locked, "Unlock the local vault to use AI settings".into()));
    }
    if !datastore.is_encrypted() {
        return Err(HttpErrorJson::new(Status::ServiceUnavailable, "AI requires an encrypted local vault".into()));
    }
    Ok(())
}

fn datastore_error(error: DatastoreError) -> HttpErrorJson {
    match error {
        DatastoreError::Locked => HttpErrorJson::new(Status::Locked, "Unlock the local vault to use AI settings".into()),
        other => HttpErrorJson::from(other),
    }
}

fn native_secret_store_available(config: &AWConfig) -> bool {
    cfg!(any(target_os = "linux", target_os = "macos", target_os = "windows"))
        && config.auth.sessions.is_some()
}

fn proxy_error(error: EgressReasonCodeV1) -> HttpErrorJson {
    let status = match error {
        EgressReasonCodeV1::KillSwitch => Status::Forbidden,
        EgressReasonCodeV1::ApprovalExpired | EgressReasonCodeV1::PolicyChanged => Status::Conflict,
        _ => Status::Forbidden,
    };
    let reason = serde_json::to_string(&error).unwrap_or_else(|_| "\"denied\"".into());
    HttpErrorJson::new(status, format!("AI request denied by the Privacy Firewall: {reason}"))
}

fn custom_profile(settings: &AISettingsV1, profile_id: &str) -> Result<AIEndpointProfileV1, HttpErrorJson> {
    if settings.mode != AIAccessModeV1::CustomEndpoint
        || settings.active_connection_id.as_deref() != Some(profile_id)
    {
        return Err(HttpErrorJson::new(Status::Forbidden, "Custom Endpoint is Off or unavailable".into()));
    }
    settings.profiles.iter().find(|profile| profile.profile_id == profile_id).cloned()
        .ok_or_else(|| HttpErrorJson::new(Status::Conflict, "The active Custom Endpoint profile was removed".into()))
}

fn custom_policy(
    datastore: &Datastore,
    trust: &EgressPolicyTrust,
    profile: &AIEndpointProfileV1,
) -> Result<VerifiedPolicyV1, HttpErrorJson> {
    active_policy(datastore, trust)?.for_custom_endpoint(profile).map_err(proxy_error)
}

fn random_insight_id() -> Result<String, HttpErrorJson> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new().fill(&mut bytes)
        .map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI history is unavailable".into()))?;
    Ok(format!("i-{}", bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()))
}

fn request_payload(request: AIUserRequestV1) -> Result<(Value, AIRequestFeatureV1), HttpErrorJson> {
    request.validate().map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "The AI request must contain a bounded question and minimized aggregate".into()))?;
    Ok((json!({ "question": request.question, "aggregate": request.aggregate }), request.feature))
}

fn ai_approval_expiry(request: &ApproveAIRequestV1, now: DateTime<Utc>) -> Result<DateTime<Utc>, Status> {
    if request.scope != EgressApprovalScopeV1::Once || request.expires_at.is_some() {
        return Err(Status::BadRequest);
    }
    Ok(now + Duration::minutes(5))
}

#[get("/status")]
pub async fn status(
    state: &State<ServerState>,
    config: &State<AWConfig>,
    proxy: &State<EgressProxy>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<AIServiceStatusV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    let proxy = proxy.inner().clone();
    let trust = trust.inner().clone();
    let native_secret_store_available = native_secret_store_available(config.inner());
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        let settings = datastore.get_ai_settings().map_err(datastore_error)?;
        let kill_switch = proxy.kill_switch_enabled().unwrap_or(true);
        let custom_endpoint_available = native_secret_store_available
            && !kill_switch
            && active_policy(&datastore, &trust).is_ok_and(|policy| {
                policy.policy().destinations.iter().any(|destination| {
                    destination.id == "custom-endpoint"
                        && destination.status == aw_models::EgressDestinationStatusV1::Planned
                        && destination.https_origin.is_none()
                        && destination.allowed_purposes.iter().any(|id| id == "ai.custom_endpoint")
                }) && policy.policy().purposes.iter().any(|purpose| {
                    purpose.id == "ai.custom_endpoint" && purpose.destination_id == "custom-endpoint"
                })
            });
        Ok::<_, HttpErrorJson>(Json(AIServiceStatusV1 {
            schema_version: 1,
            mode: settings.mode,
            revision: settings.revision,
            peak_ai_available: false,
            custom_endpoint_available,
            native_secret_store_available,
        }))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI status is unavailable".into()))?
}

#[get("/settings")]
pub async fn settings_get(state: &State<ServerState>) -> Result<Json<AISettingsV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        datastore.get_ai_settings().map(Json).map_err(datastore_error)
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI settings are unavailable".into()))?
}

#[put("/settings", data = "<request>", format = "application/json")]
pub async fn settings_update(
    request: Json<UpdateAISettingsRequestV1>,
    state: &State<ServerState>,
    config: &State<AWConfig>,
    trust: &State<EgressPolicyTrust>,
) -> Result<Json<AISettingsV1>, HttpErrorJson> {
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let native_secret_store_available = native_secret_store_available(config.inner());
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        request.settings.validate().map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "Invalid AI settings".into()))?;
        match request.settings.mode {
            AIAccessModeV1::Off => {},
            AIAccessModeV1::PeakAi => {
                return Err(HttpErrorJson::new(Status::ServiceUnavailable, "Peak AI has no approved provider registry or service contract".into()));
            }
            AIAccessModeV1::CustomEndpoint => {
                if !native_secret_store_available {
                    return Err(HttpErrorJson::new(Status::ServiceUnavailable, "A native secret store is unavailable on this platform".into()));
                }
                let profile_id = request.settings.active_connection_id.as_deref().unwrap_or_default();
                let profile = custom_profile(&request.settings, profile_id)?;
                custom_policy(&datastore, &trust, &profile)?;
            }
        }
        datastore.compare_and_set_ai_settings(request.expected_revision, request.settings)
            .map_err(datastore_error)?
            .map(Json)
            .ok_or_else(|| HttpErrorJson::new(Status::Conflict, "AI settings changed; reload and review again".into()))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI settings are unavailable".into()))?
}

#[post("/connection-test", data = "<request>", format = "application/json")]
pub async fn connection_test(
    request: Json<ConnectionTestRequestV1>,
    state: &State<ServerState>,
    config: &State<AWConfig>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<ConnectionTestResponseV1>, HttpErrorJson> {
    let profile = request.into_inner().profile;
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    let native_secret_store_available = native_secret_store_available(config.inner());
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        if !native_secret_store_available {
            return Err(HttpErrorJson::new(Status::ServiceUnavailable, "Custom Endpoint is unavailable on this platform".into()));
        }
        let policy = active_policy(&datastore, &trust)?;
        let (http_status, resolved_addresses) = proxy.test_custom_endpoint(&policy, &profile, Utc::now()).map_err(proxy_error)?;
        Ok(Json(ConnectionTestResponseV1 {
            schema_version: 1,
            http_status,
            tls_verified: true,
            resolved_addresses,
            disclosure_status: "not_verified",
        }))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "Custom Endpoint test is unavailable".into()))?
}

#[post("/preview", data = "<request>", format = "application/json")]
pub async fn preview(
    request: Json<AIUserRequestV1>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<AIRequestPreviewV1>, HttpErrorJson> {
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        let settings = datastore.get_ai_settings().map_err(datastore_error)?;
        let profile = custom_profile(&settings, &request.profile_id)?;
        let policy = custom_policy(&datastore, &trust, &profile)?;
        let (payload, feature) = request_payload(request)?;
        let purpose = policy.policy().purposes.iter()
            .find(|purpose| purpose.id == "ai.custom_endpoint")
            .ok_or_else(|| HttpErrorJson::new(Status::ServiceUnavailable, "The signed AI purpose is unavailable".into()))?;
        let destination_id = policy.custom_endpoint_destination_id()
            .ok_or_else(|| HttpErrorJson::new(Status::ServiceUnavailable, "The Custom Endpoint is unavailable".into()))?;
        let egress_request = aw_models::EgressRequestV1 {
            schema_version: 1,
            destination_id,
            purpose_id: purpose.id.clone(),
            retention_id: purpose.retention_id.clone(),
            payload,
        };
        let decision = proxy.preview_custom_ai(&policy, egress_request, feature, Utc::now(), chrono::Local::now().offset().local_minus_utc());
        Ok(Json(AIRequestPreviewV1 {
            profile_id: profile.profile_id,
            origin: profile.origin,
            model_id: profile.model_id,
            purpose_id: purpose.id.clone(),
            retention_disclosure: format!("{} — User notes are not verified: region {}; retention {}; training {}", purpose.retention_disclosure, profile.region_note, profile.retention_note, profile.training_note),
            decision,
        }))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI preview is unavailable".into()))?
}

#[post("/approve", data = "<request>", format = "application/json")]
pub async fn approve(
    request: Json<ApproveAIRequestV1>,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<EgressApprovalV1>, HttpErrorJson> {
    let request = request.into_inner();
    let now = Utc::now();
    let expires_at = ai_approval_expiry(&request, now)
        .map_err(|_| HttpErrorJson::new(Status::BadRequest, "AI approvals must be one-time with server-set expiry".into()))?;
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        let settings = datastore.get_ai_settings().map_err(datastore_error)?;
        let profile = custom_profile(&settings, &request.profile_id)?;
        let policy = custom_policy(&datastore, &trust, &profile)?;
        let guard = proxy.begin_send().map_err(proxy_error)?;
        let approved = guard.approve(&policy, &request.preview_id, EgressApprovalScopeV1::Once, Some(expires_at), now.clone(), chrono::Local::now().offset().local_minus_utc()).map_err(proxy_error)?;
        datastore.get_egress_approval(approved.approval_id(), now)
            .map_err(datastore_error)?
            .map(Json)
            .ok_or_else(|| HttpErrorJson::new(Status::Conflict, "AI approval expired".into()))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI approval is unavailable".into()))?
}

#[post("/native-preview/<preview_id>", data = "<request>", format = "application/json")]
pub async fn native_preview(
    preview_id: String,
    request: Json<NativePreviewRequestV1>,
    ai_send: AiSendOnly,
    state: &State<ServerState>,
    config: &State<AWConfig>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<AIRequestPreviewV1>, HttpErrorJson> {
    let approval_id = request.into_inner().approval_id;
    if approval_id.len() != 64 || !approval_id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(HttpErrorJson::new(Status::BadRequest, "Invalid AI approval ID".into()));
    }
    if !ai_send.0 || !native_secret_store_available(config.inner()) {
        return Err(HttpErrorJson::new(Status::Forbidden, "Only the native AI confirmation path can read this preview".into()));
    }
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        let settings = datastore.get_ai_settings().map_err(datastore_error)?;
        let profile_id = settings.active_connection_id.as_deref().unwrap_or_default();
        let profile = custom_profile(&settings, profile_id)?;
        let policy = custom_policy(&datastore, &trust, &profile)?;
        let approval = datastore.get_egress_approval(&approval_id, Utc::now()).map_err(datastore_error)?
            .ok_or_else(|| HttpErrorJson::new(Status::Conflict, "The AI approval is unavailable".into()))?;
        let destination_id = policy.custom_endpoint_destination_id()
            .ok_or_else(|| HttpErrorJson::new(Status::ServiceUnavailable, "The Custom Endpoint is unavailable".into()))?;
        let purpose = policy.policy().purposes.iter()
            .find(|purpose| purpose.id == "ai.custom_endpoint")
            .ok_or_else(|| HttpErrorJson::new(Status::ServiceUnavailable, "The signed AI purpose is unavailable".into()))?;
        if approval.destination_id != destination_id
            || approval.purpose_id != purpose.id
            || approval.retention_id != purpose.retention_id
            || approval.policy_version != policy.policy().version
        {
            return Err(HttpErrorJson::new(Status::Conflict, "The AI approval no longer matches this preview".into()));
        }
        let decision = proxy.read_custom_ai_preview(
            &policy, &profile, &preview_id, Utc::now(), chrono::Local::now().offset().local_minus_utc(),
        ).map_err(proxy_error)?;
        Ok(Json(AIRequestPreviewV1 {
            profile_id: profile.profile_id,
            origin: profile.origin,
            model_id: profile.model_id,
            purpose_id: purpose.id.clone(),
            retention_disclosure: format!("{} — User notes are not verified: region {}; retention {}; training {}", purpose.retention_disclosure, profile.region_note, profile.retention_note, profile.training_note),
            decision,
        }))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI preview confirmation is unavailable".into()))?
}

#[post("/send", data = "<request>", format = "application/json")]
pub async fn send(
    request: Json<SendAIRequestV1>,
    ai_send: AiSendOnly,
    credential: NativeAICredential,
    state: &State<ServerState>,
    trust: &State<EgressPolicyTrust>,
    proxy: &State<EgressProxy>,
) -> Result<Json<AIResultV1>, HttpErrorJson> {
    if !ai_send.0 { return Err(HttpErrorJson::new(Status::Forbidden, "AI send requires a native secret-store session".into())); }
    let secret = credential.0;
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    let trust = trust.inner().clone();
    let proxy = proxy.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        let settings = datastore.get_ai_settings().map_err(datastore_error)?;
        let profile = custom_profile(&settings, &request.profile_id)?;
        if request.credential_ref != profile.credential_ref {
            return Err(HttpErrorJson::new(Status::Conflict, "The credential changed after request review".into()));
        }
        let bearer = match profile.authentication {
            aw_models::AIAuthenticationV1::None if secret.is_none() => None,
            aw_models::AIAuthenticationV1::Bearer => Some(secret.as_ref().map(|value| value.as_str())
                .ok_or_else(|| HttpErrorJson::new(Status::Forbidden, "The native credential is unavailable".into()))?),
            _ => return Err(HttpErrorJson::new(Status::Forbidden, "The native credential is unavailable".into())),
        };
        let policy = custom_policy(&datastore, &trust, &profile)?;
        let (_, response) = proxy.send_custom_ai_approval(
            &policy, &profile, &request.preview_id, &request.approval_id, bearer,
            Utc::now(), chrono::Local::now().offset().local_minus_utc(),
        ).map_err(proxy_error)?;
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(HttpErrorJson::new(Status::BadGateway, "The AI endpoint returned an invalid response".into()));
        }
        let value: Value = serde_json::from_slice(&response)
            .map_err(|_| HttpErrorJson::new(Status::BadGateway, "The AI endpoint returned an invalid response".into()))?;
        let text = value.pointer("/choices/0/message/content").and_then(Value::as_str)
            .ok_or_else(|| HttpErrorJson::new(Status::BadGateway, "The AI endpoint returned an unsupported response".into()))?;
        let result = AIResultV1 {
            schema_version: 1,
            source_mode: AIAccessModeV1::CustomEndpoint,
            profile_label: profile.display_name,
            model_id: profile.model_id,
            text: text.to_string(),
        };
        result.validate().map_err(|_| HttpErrorJson::new(Status::BadGateway, "The AI endpoint returned an unsupported response".into()))?;
        Ok(Json(result))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI send is unavailable".into()))?
}

#[get("/history")]
pub async fn history_get(state: &State<ServerState>) -> Result<Json<AIInsightHistoryV1>, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        datastore.get_ai_insight_history().map(Json).map_err(datastore_error)
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI history is unavailable".into()))?
}

#[post("/history", data = "<request>", format = "application/json")]
pub async fn history_save(
    request: Json<SaveInsightRequestV1>,
    state: &State<ServerState>,
) -> Result<Json<AIInsightHistoryV1>, HttpErrorJson> {
    let request = request.into_inner();
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        request.result.validate().map_err(|_| HttpErrorJson::new(Status::UnprocessableEntity, "Invalid AI result".into()))?;
        let insight = AIInsightV1 {
            insight_id: random_insight_id()?,
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source_mode: request.result.source_mode,
            profile_label: request.result.profile_label,
            model_id: request.result.model_id,
            feature: request.feature,
            text: request.result.text,
        };
        datastore.save_ai_insight(insight).map(Json).map_err(datastore_error)
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI history is unavailable".into()))?
}

#[delete("/history/<insight_id>")]
pub async fn history_delete(
    insight_id: String,
    state: &State<ServerState>,
) -> Result<Status, HttpErrorJson> {
    let datastore = state.datastore.clone();
    rocket::tokio::task::spawn_blocking(move || {
        require_encrypted(&datastore)?;
        datastore.delete_ai_insight(&insight_id).map_err(datastore_error)?
            .map(|_| Status::Ok)
            .ok_or_else(|| HttpErrorJson::new(Status::NotFound, "Saved AI insight does not exist".into()))
    }).await.map_err(|_| HttpErrorJson::new(Status::ServiceUnavailable, "AI history is unavailable".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_insight_ids_start_with_a_valid_identifier_character() {
        assert!(random_insight_id().unwrap().starts_with("i-"));
    }

    #[test]
    fn native_ai_credential_header_is_single_bounded_and_optional() {
        assert!(native_ai_credential(&[]).unwrap().is_none());
        assert_eq!(native_ai_credential(&["synthetic-token"]).unwrap().unwrap().as_str(), "synthetic-token");
        assert_eq!(native_ai_credential(&["one", "two"]).unwrap_err(), Status::BadRequest);
        assert_eq!(native_ai_credential(&["token with spaces"]).unwrap_err(), Status::BadRequest);
        assert_eq!(native_ai_credential(&[&"x".repeat(8193)]).unwrap_err(), Status::BadRequest);
    }

    #[test]
    fn ai_approval_uses_a_server_set_one_time_expiry() {
        let now = Utc::now();
        let request = ApproveAIRequestV1 {
            profile_id: "profile_01".into(), preview_id: "preview_01".into(),
            scope: EgressApprovalScopeV1::Once, expires_at: None,
        };
        assert_eq!(ai_approval_expiry(&request, now).unwrap(), now + Duration::minutes(5));
        let mut invalid = request;
        invalid.scope = EgressApprovalScopeV1::TimeLimited;
        assert_eq!(ai_approval_expiry(&invalid, now), Err(Status::BadRequest));
    }
}
