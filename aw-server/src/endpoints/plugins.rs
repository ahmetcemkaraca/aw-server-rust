use rocket::serde::json::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct PluginServiceStatusV1 {
    pub schema_version: u16,
    pub runtime_compiled: bool,
    pub runtime_available: bool,
    pub marketplace_available: bool,
    pub signed_purpose_available: bool,
    pub blocker_ids: Vec<&'static str>,
}

#[get("/status")]
pub fn status() -> Json<PluginServiceStatusV1> {
    Json(PluginServiceStatusV1 {
        schema_version: 1,
        runtime_compiled: cfg!(feature = "plugin-runtime"),
        runtime_available: false,
        marketplace_available: false,
        signed_purpose_available: false,
        blocker_ids: vec![
            "capability_host_broker",
            "sandbox_escape_review",
            "publisher_trust_registry",
            "package_review_and_provenance",
            "marketplace_operations",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::status;

    #[test]
    fn sandbox_execution_and_marketplace_remain_closed_without_host_services() {
        let status = status().into_inner();
        assert_eq!(status.runtime_compiled, cfg!(feature = "plugin-runtime"));
        assert!(!status.runtime_available);
        assert!(!status.marketplace_available);
        assert!(!status.signed_purpose_available);
    }
}
