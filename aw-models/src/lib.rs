#[macro_use]
extern crate log;

// TODO: Move me to an appropriate place
#[cfg(test)] // Only macro use for tests
macro_rules! json_map {
    { $( $key:literal : $value:expr),* } => {{
        use serde_json::{Value};
        use serde_json::map::Map;
        #[allow(unused_mut)]
        let mut map : Map<String, Value> = Map::new();
        $(
          map.insert( $key.to_string(), json!($value) );
        )*
        map
    }};
}

mod bucket;
mod ai;
mod capture;
mod duration;
mod entitlement;
mod egress;
mod event;
mod freelancer;
mod info;
mod plugin;
mod query;
mod settings;
mod sync;
mod timeinterval;
mod tryvec;

pub use self::bucket::Bucket;
pub use self::capture::CapturePolicy;
pub use self::bucket::BucketMetadata;
pub use self::ai::{
    AIAccessModeV1, AIAuthenticationV1, AIContractErrorV1, AIDestinationTypeV1, AIEndpointProfileV1,
    AIEndpointProtocolV1, AIProviderV1, AIRequestFeatureV1, AIRequestPreviewV1,
    AIInsightHistoryV1, AIInsightV1, AIResultV1, AISettingsV1, AIUserRequestV1, SignedAIProviderRegistryV1,
    AI_MAX_AGGREGATE_BYTES_V1, AI_MAX_ENDPOINT_PROFILES_V1, AI_MAX_HISTORY_ENTRIES_V1,
    AI_MAX_QUESTION_BYTES_V1, AI_MAX_RESULT_BYTES_V1, AI_SCHEMA_VERSION_V1,
};
pub use self::bucket::BucketsExport;
pub use self::event::Event;
pub use self::freelancer::{
    calculate_invoice_subtotal_minor, freelancer_report_signature_message_v1,
    round_freelancer_duration,
    ApprovedTimesheetContractErrorV1, ApprovedTimesheetV1,
    APPROVED_TIMESHEET_MAX_NOTE_BYTES_V1, APPROVED_TIMESHEET_MAX_SECONDS_PER_DAY_V1,
    APPROVED_TIMESHEET_SCHEMA_VERSION_V1, FreelancerCategoryRuleV1,
    FreelancerContractErrorV1, FreelancerProjectV1, FreelancerRoundingModeV1,
    FreelancerWorkspaceV1, InvoiceDraftStatusV1, InvoiceDraftV1, InvoiceTaxStatusV1,
    SignedClientReportV1, FREELANCER_REPORT_SIGNATURE_DOMAIN_V1,
    FREELANCER_MAX_CATEGORY_RULES_V1, FREELANCER_MAX_PROJECTS_V1,
    FREELANCER_MAX_SAFE_MINOR_UNITS_V1, FREELANCER_MAX_WORKSPACE_BYTES_V1,
    INVOICE_DRAFT_MAX_DAYS_V1,
};
pub use self::entitlement::{
    CommercialPackageV1, EntitlementClaimsV1, EntitlementContractErrorV1, EntitlementRevocationSnapshotV1,
    EntitlementSigningPayloadV1, SignedEntitlementV1, ENTITLEMENT_MAX_DEVICES_V1,
    ENTITLEMENT_MAX_FEATURES_V1, ENTITLEMENT_MAX_REVOCATIONS_V1,
    ENTITLEMENT_SCHEMA_VERSION_V1, PackageCatalogV1, PACKAGE_CATALOG_SCHEMA_VERSION_V1,
};
pub use self::egress::{
    AfterHoursV1, EgressApprovalScopeV1, EgressApprovalV1, EgressDecisionV1, EgressDestinationStatusV1,
    EgressDestinationV1, EgressOutcomeV1, EgressPatternV1, EgressPolicyBundleV1,
    EgressPolicyDiffV1, EgressPolicyErrorV1, EgressPolicyV1, EgressPreviewV1, EgressPurposeV1, EgressReasonCodeV1,
    EgressReceiptV1, EgressRequestV1, EgressRuleActionV1, EgressRuleV1,
    EgressMatchKindV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
};
pub use self::info::Info;
pub use self::plugin::{
    plugin_capability_diff_v1, validate_plugin_input_v1, validate_plugin_output_v1,
    validate_plugin_write_intent_v1, PluginAIIntentV1,
    PluginBackgroundCapabilityV1, PluginCapabilitiesV1, PluginCapabilityDiffV1,
    PluginContractErrorV1, PluginDataClassV1, PluginDestructiveActionV1,
    PluginDestructiveCapabilityV1, PluginDestructiveIntentV1, PluginInvocationOutputV1,
    PluginInputRecordV1, PluginInvocationInputV1, PluginManifestV1, PluginNetworkCapabilityV1, PluginNetworkIntentV1,
    PluginOwnedEventV1,
    PluginPayloadClassV1, PluginReadCapabilityV1, PluginStorageCapabilityV1,
    PluginStorageIntentV1, PluginUISurfaceV1, PluginUIOutputV1, PluginWriteCapabilityV1,
    PluginWriteIntentV1, ValidatedPluginInputV1, ValidatedPluginOutputV1,
    SignedPluginPackageV1, PLUGIN_MAX_BACKGROUND_MEMORY_BYTES_V1,
    PLUGIN_MAX_BACKGROUND_RUNTIME_MS_V1, PLUGIN_MAX_GRANTS_V1,
    PLUGIN_MAX_STORAGE_BYTES_V1, PLUGIN_MAX_PLUGIN_EVENT_BYTES_V1, PLUGIN_AGGREGATE_FIELDS_V1,
    PLUGIN_MAX_INTENT_PAYLOAD_BYTES_V1,
    PLUGIN_MAX_INVOCATION_INPUT_BYTES_V1, PLUGIN_MAX_INVOCATION_OUTPUT_BYTES_V1,
    PLUGIN_MAX_INVOCATION_RECORDS_V1, PLUGIN_MIN_BACKGROUND_INTERVAL_SECONDS_V1,
    PLUGIN_SCHEMA_VERSION_V1,
};
pub use self::query::Query;
pub use self::settings::Settings;
pub use self::settings::{
    Class, ClassData, ClassRule, NewReleaseCheckData, UserSatisfactionPollData, View, ViewElement,
};
pub use self::sync::{
    DevicePublicIdentityV1, EncryptedKeyTransferV1, PairingConfirmationV1, PairingInvitationV1,
    PairingOfferV1, PairingResponseV1, RecoveryKitV1, SyncChunkHeaderV1, SyncEnvelopeV1,
    SyncBucketDescriptorV1, SyncOperationKindV1, SyncRelayOperationV1, SyncRelayRequestV1, SyncRelayResponseV1,
    SyncWireErrorV1, SYNC_CHALLENGE_BYTES, SYNC_EGRESS_PURPOSE_V1,
    SYNC_ID_BYTES, SYNC_KEY_BYTES,
    SYNC_MAX_CHUNK_BYTES, SYNC_MAX_KEY_TRANSFER_BYTES, SYNC_NONCE_BYTES, SYNC_SCHEMA_VERSION_V1,
    SYNC_TAG_BYTES,
};
pub use self::timeinterval::TimeInterval;
pub use self::tryvec::TryVec;
