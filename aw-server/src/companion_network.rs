//! Native access to the same signed-policy network gates as the local HTTP API.
use aw_datastore::Datastore;
use aw_egress::EgressProxy;
use crate::endpoints::{EgressPolicyTrust, HttpErrorJson, SyncEgressControlRequest,
    local_sync_status, local_egress_status, active_policy, preview_local_policy,
    accept_local_policy, set_local_sync_enabled, run_local_sync};
use aw_models::{EgressDestinationStatusV1, EgressPolicyDiffV1, SignedEgressPolicyBundleV1, SYNC_EGRESS_PURPOSE_V1};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct CompanionNetwork {
    store: Datastore,
    trust: EgressPolicyTrust,
    proxy: EgressProxy,
    running: AtomicBool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPreview { bundle: SignedEgressPolicyBundleV1 }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyAccept {
    bundle: SignedEgressPolicyBundleV1,
    expected_diff: EgressPolicyDiffV1,
    #[serde(rename = "userConfirmed")]
    user_confirmed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnableRequest {
    enabled: bool,
    destination_id: Option<String>,
    purpose_id: Option<String>,
    #[serde(rename = "userConfirmed")]
    user_confirmed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KillSwitchRequest { enabled: bool }

struct Running<'a>(&'a AtomicBool);
impl Drop for Running<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

fn parse<T: DeserializeOwned>(arguments: Value) -> Result<T, String> {
    serde_json::from_value(arguments).map_err(|_| "The native network request is invalid".into())
}

fn error_message(error: HttpErrorJson) -> String {
    serde_json::to_value(error).ok().and_then(|value| value["message"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "The native network operation could not be completed".into())
}

fn value<T: serde::Serialize>(result: T) -> Result<Value, String> {
    serde_json::to_value(result).map_err(|_| "The native network result could not be encoded".into())
}

impl CompanionNetwork {
    pub fn new(store: Datastore) -> Self { Self::from_release_keys(store, HashMap::new()) }

    pub fn with_feature_access(mut self, access: std::sync::Arc<aw_entitlements::RuntimeFeatureAccessV1>) -> Self {
        self.proxy = self.proxy.with_sync_access(access);
        self
    }

    pub fn from_release_keys(store: Datastore, keys: HashMap<String, Vec<u8>>) -> Self {
        let proxy = EgressProxy::new(store.clone());
        Self::from_parts(store, EgressPolicyTrust::from_release_keys(keys), proxy)
    }

    pub fn from_release_resource(store: Datastore, bytes: &[u8]) -> Result<Self, &'static str> {
        crate::companion_release_trust::parse_release_trust(bytes).map(|keys| Self::from_release_keys(store, keys))
    }

    pub(crate) fn from_parts(store: Datastore, trust: EgressPolicyTrust, proxy: EgressProxy) -> Self {
        Self { store, trust, proxy, running: AtomicBool::new(false) }
    }

    pub fn invoke(&self, command: &str, arguments: Value) -> Option<Result<Value, String>> {
        if let Some(result) = crate::feature_access::invoke(&self.proxy.sync_access(),command,arguments.clone()) {
            return Some(result);
        }
        Some(match command {
            "sync_network_status" => self.status(arguments),
            "sync_signed_destinations" => self.destinations(arguments),
            "preview_sync_policy" => (|| {
                let request: PolicyPreview = parse(arguments)?;
                value(preview_local_policy(&self.store, &self.trust, &request.bundle).map_err(error_message)?)
            })(),
            "accept_sync_policy" => (|| {
                let request: PolicyAccept = parse(arguments)?;
                accept_local_policy(&self.store, &self.trust, &self.proxy, &request.bundle,
                    &request.expected_diff, request.user_confirmed).map_err(error_message)?;
                Ok(Value::Null)
            })(),
            "set_sync_enabled" => (|| {
                let request: EnableRequest = parse(arguments)?;
                if request.enabled && !request.user_confirmed {
                    return Err("Confirm the selected signed sync destination before enabling network sync".into());
                }
                value(set_local_sync_enabled(&self.store, &self.trust, &self.proxy, &SyncEgressControlRequest {
                    enabled: request.enabled, destination_id: request.destination_id, purpose_id: request.purpose_id,
                }, true).map_err(error_message)?)
            })(),
            "run_sync_once" => self.run(arguments),
            "set_egress_kill_switch" => (|| {
                let request: KillSwitchRequest = parse(arguments)?;
                self.proxy.set_kill_switch(request.enabled).map_err(|_| "The privacy kill switch could not be changed")?;
                Ok(Value::Null)
            })(),
            _ => return None,
        })
    }

    fn status(&self, arguments: Value) -> Result<Value, String> {
        let _: EmptyRequest = parse(arguments)?;
        let sync = local_sync_status(&self.store).map_err(error_message)?;
        let egress = local_egress_status(&self.store, &self.proxy, &self.trust).map_err(error_message)?;
        Ok(json!({"sync":sync, "egress":egress, "running":self.running.load(Ordering::Acquire)}))
    }

    fn destinations(&self, arguments: Value) -> Result<Value, String> {
        let _: EmptyRequest = parse(arguments)?;
        let policy = active_policy(&self.store, &self.trust).map_err(error_message)?;
        Ok(Value::Array(policy.policy().purposes.iter().filter(|purpose| {
            purpose.id == SYNC_EGRESS_PURPOSE_V1 && policy.policy().destinations.iter().any(|destination| {
                destination.id == purpose.destination_id && matches!(destination.status,
                    EgressDestinationStatusV1::Available | EgressDestinationStatusV1::Beta | EgressDestinationStatusV1::Experimental)
            })
        }).map(|purpose| json!({
            "destination_id":purpose.destination_id, "label":purpose.destination_id,
            "purpose_id":purpose.id, "retention_id":purpose.retention_id,
            "retention_disclosure":purpose.retention_disclosure, "allowed_fields":purpose.allowed_fields,
        })).collect()))
    }

    fn run(&self, arguments: Value) -> Result<Value, String> {
        let _: EmptyRequest = parse(arguments)?;
        self.running.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "A native sync cycle is already running")?;
        let _running = Running(&self.running);
        match run_local_sync(&self.store, &self.trust, &self.proxy) {
            Ok(Value::Object(mut result)) => {
                result.insert("success".into(), json!(true));
                result.insert("retryable".into(), json!(false));
                Ok(Value::Object(result))
            }
            Ok(_) => Err("The shared sync result is invalid".into()),
            Err((error, retryable)) => Ok(json!({"success":false, "retryable":retryable, "error":error_message(error)})),
        }
    }

    pub fn pause(&self) -> Result<(), String> {
        self.proxy.set_sync_enabled(false, None, None).map_err(|_| "Sync could not be paused".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod entitlement_fixture { include!("../tests/support/entitlement.rs"); }
    use aw_models::{Bucket, BucketMetadata, EgressDestinationStatusV1, EgressDestinationV1,
        EgressPolicyBundleV1, EgressPurposeV1, SignedEgressPolicyBundleV1, TryVec, Event};
    use aw_sync_e2ee::{SyncRelayRequestV1, SyncRelayResponseV1, SyncRelayOperationV1,
        create_vault_data_key, generate_account_root_key, generate_device_identity};
    use aw_datastore::{SyncDeviceIdentity, SyncKeyMaterial, SyncSnapshotV1};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{Duration, Utc};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Relay {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        fail: bool,
    }

    impl aw_egress::EgressTransport for Relay {
        fn send(&self, _: &EgressDestinationV1, _: &EgressPurposeV1, _: &[u8]) -> Result<(), aw_models::EgressReasonCodeV1> {
            panic!("Sync must use the shared request transport")
        }

        fn request(&self, _: &EgressDestinationV1, _: &EgressPurposeV1, payload: &[u8]) -> Result<Vec<u8>, aw_models::EgressReasonCodeV1> {
            self.requests.lock().unwrap().push(payload.to_vec());
            if self.fail { return Err(aw_models::EgressReasonCodeV1::NetworkUnavailable); }
            let request: SyncRelayRequestV1 = serde_json::from_slice(payload).unwrap();
            let mut response = SyncRelayResponseV1 { schema_version: 1, ..Default::default() };
            if request.operation == SyncRelayOperationV1::PutIfAbsent { response.inserted = Some(true); }
            serde_json::to_vec(&response).map_err(|_| aw_models::EgressReasonCodeV1::InvalidPayload)
        }
    }

    fn signed_policy() -> (SignedEgressPolicyBundleV1, HashMap<String, Vec<u8>>) {
        let key = Ed25519KeyPair::from_seed_unchecked(&[0xC1; 32]).unwrap();
        let mut signed = SignedEgressPolicyBundleV1 {
            schema_version: 1, signer_key_id: "synthetic-release".into(), signature: Vec::new(),
            bundle: EgressPolicyBundleV1 {
                schema_version: 1, version: 1, hard_deny_version: 1,
                destinations: vec![EgressDestinationV1 {
                    id: "synthetic-sync".into(), status: EgressDestinationStatusV1::Experimental,
                    https_origin: Some("https://sync.example.invalid".into()),
                    allowed_purposes: vec!["sync-object-v1".into()],
                }],
                purposes: vec![EgressPurposeV1 {
                    id: "sync-object-v1".into(), destination_id: "synthetic-sync".into(), endpoint_path: "/objects".into(),
                    retention_id: "opaque-only".into(), retention_disclosure: "Synthetic encrypted envelopes only".into(),
                    allowed_fields: vec!["/schema_version".into(), "/operation".into(), "/object_id".into(),
                        "/vault_id".into(), "/cursor".into(), "/limit".into(), "/envelope/*".into()],
                }], organization_rules: Vec::new(),
            },
        };
        signed.signature = key.sign(&aw_egress::policy_bundle_signing_bytes(&signed).unwrap()).as_ref().to_vec();
        (signed, HashMap::from([("synthetic-release".into(), key.public_key().as_ref().to_vec())]))
    }

    fn store() -> Datastore { Datastore::open_encrypted(":memory:".into(), "native-network-fixture-key-".repeat(3)).unwrap() }

    fn call(controller: &CompanionNetwork, command: &str, arguments: Value) -> Result<Value, String> {
        controller.invoke(command, arguments).expect("known network command")
    }

    fn prepare_keys(store: &Datastore) {
        let identity = generate_device_identity().unwrap();
        store.create_sync_device_identity(&SyncDeviceIdentity::new(
            *identity.device_id_bytes(), identity.secret_for_storage(), identity.signing_seed_for_storage(),
        )).unwrap();
        let root = generate_account_root_key().unwrap();
        let vault = [0xC2; 16];
        let (data, wrapped) = create_vault_data_key(&root, &URL_SAFE_NO_PAD.encode(vault), 1).unwrap();
        let snapshot = aw_sync_e2ee::encrypt_snapshot(&data, b"synthetic initial snapshot").unwrap();
        store.install_sync_recovery(SyncKeyMaterial::new(root.secret_for_storage(), vault, 1,
            URL_SAFE_NO_PAD.decode(wrapped.nonce).unwrap().try_into().unwrap(),
            URL_SAFE_NO_PAD.decode(wrapped.ciphertext).unwrap().try_into().unwrap()),
            SyncSnapshotV1::new(URL_SAFE_NO_PAD.decode(snapshot.snapshot_id).unwrap().try_into().unwrap(), snapshot.envelopes)).unwrap();
        let peer = generate_device_identity().unwrap();
        let public = peer.public_identity();
        store.record_sync_pairing(None, [0xC3; 16], *peer.device_id_bytes(),
            URL_SAFE_NO_PAD.decode(public.x25519_public_key).unwrap().try_into().unwrap(),
            URL_SAFE_NO_PAD.decode(public.ed25519_public_key).unwrap().try_into().unwrap(), Utc::now().to_rfc3339()).unwrap();
        store.confirm_sync_recovery_saved(Utc::now().to_rfc3339()).unwrap();
        store.create_bucket(&Bucket {
            bid: None, id: "aw-stopwatch".into(), _type: "general.stopwatch".into(), client: "synthetic-companion".into(),
            hostname: "synthetic".into(), created: None, data: Default::default(), metadata: BucketMetadata::default(),
            events: Some(TryVec::new(vec![Event::new(Utc::now() - Duration::hours(1), Duration::minutes(10),
                json!({"label":"private-manual-fixture", "running":false}).as_object().unwrap().clone())])), last_updated: None,
        }).unwrap();
    }

    fn configured(fail: bool) -> (Datastore, CompanionNetwork, Relay) {
        let store = store();
        prepare_keys(&store);
        let (bundle, keys) = signed_policy();
        let relay = Relay { fail, ..Default::default() };
        let proxy = EgressProxy::with_transport(store.clone(), relay.clone())
            .with_sync_access(entitlement_fixture::access());
        let controller = CompanionNetwork::from_parts(store.clone(), EgressPolicyTrust::from_release_keys(keys), proxy);
        let diff = call(&controller, "preview_sync_policy", json!({"bundle":bundle})).unwrap();
        call(&controller, "accept_sync_policy", json!({"bundle":bundle, "expected_diff":diff, "userConfirmed":true})).unwrap();
        call(&controller, "set_egress_kill_switch", json!({"enabled":false})).unwrap();
        (store, controller, relay)
    }

    #[test]
    fn empty_release_trust_keeps_native_network_off_without_transport_requests() {
        let store = store();
        let default = CompanionNetwork::new(store.clone());
        let status = call(&default, "sync_network_status", json!({})).unwrap();
        assert_eq!(status["egress"]["trusted_policy_keys"], 0);
        assert_eq!(status["sync"]["enabled"], false);
        let relay = Relay::default();
        let controller = CompanionNetwork::from_parts(store.clone(), EgressPolicyTrust::default(),
            EgressProxy::with_transport(store.clone(), relay.clone()));
        let (bundle, _) = signed_policy();
        assert!(call(&controller, "preview_sync_policy", json!({"bundle":bundle})).is_err());
        assert!(call(&controller, "set_sync_enabled", json!({"enabled":true, "userConfirmed":true,
            "destination_id":"synthetic-sync", "purpose_id":"sync-object-v1"})).is_err());
        let run = call(&controller, "run_sync_once", json!({})).unwrap();
        assert_eq!(run["success"], false);
        assert_eq!(run["retryable"], false);
        assert!(relay.requests.lock().unwrap().is_empty());
        assert!(store.get_egress_policy_state().unwrap().is_none());
        store.lock().unwrap();
    }

    #[test]
    fn native_policy_and_sync_require_exact_explicit_confirmation() {
        let store = store();
        let (bundle, keys) = signed_policy();
        let controller = CompanionNetwork::from_release_keys(store.clone(), keys);
        let diff = call(&controller, "preview_sync_policy", json!({"bundle":bundle})).unwrap();
        for confirmation in [false, true] {
            let mut expected = diff.clone();
            if confirmation { expected["to_version"] = json!(999); }
            assert!(call(&controller, "accept_sync_policy", json!({"bundle":bundle,
                "expected_diff":expected, "userConfirmed":confirmation})).is_err());
        }
        assert!(store.get_egress_policy_state().unwrap().is_none());
        assert!(call(&controller, "set_sync_enabled", json!({"enabled":true, "destination_id":"synthetic-sync",
            "purpose_id":"sync-object-v1"})).is_err());
        assert!(call(&controller, "set_sync_enabled", json!({"enabled":true, "userConfirmed":false,
            "destination_id":"synthetic-sync", "purpose_id":"sync-object-v1"})).is_err());
        assert!(call(&controller, "set_sync_enabled", json!({"enabled":false, "userConfirmed":true,
            "url":"https://unreviewed.example.invalid"})).is_err());
        assert!(controller.invoke("arbitrary-network-command", json!({})).is_none());
        store.lock().unwrap();
    }

    #[test]
    fn configured_native_run_uses_shared_opaque_transport_and_stop_keeps_local_data() {
        let (store, controller, relay) = configured(false);
        let destinations = call(&controller, "sync_signed_destinations", json!({})).unwrap();
        assert_eq!(destinations[0]["destination_id"], "synthetic-sync");
        assert!(!destinations.to_string().contains("https://"));
        let enabled = call(&controller, "set_sync_enabled", json!({"enabled":true, "userConfirmed":true,
            "destination_id":"synthetic-sync", "purpose_id":"sync-object-v1"})).unwrap();
        assert_eq!(enabled["enabled"], true);
        let run = call(&controller, "run_sync_once", json!({})).unwrap();
        assert_eq!(run["success"], true);
        assert_eq!(run["retryable"], false);
        let captured = relay.requests.lock().unwrap();
        assert!(captured.len() >= 2);
        assert!(captured.iter().all(|body| !String::from_utf8_lossy(body).contains("private-manual-fixture")));
        drop(captured);
        controller.pause().unwrap();
        assert!(!store.sync_enabled().unwrap());
        assert_eq!(store.get_events("aw-stopwatch", None, None, None).unwrap().len(), 1);
        assert!(store.load_sync_key_material().unwrap().is_some());
        store.lock().unwrap();
    }

    #[test]
    fn native_transport_failure_retains_the_shared_retryable_result() {
        let (store, controller, relay) = configured(true);
        call(&controller, "set_sync_enabled", json!({"enabled":true, "userConfirmed":true,
            "destination_id":"synthetic-sync", "purpose_id":"sync-object-v1"})).unwrap();
        let result = call(&controller, "run_sync_once", json!({})).unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["retryable"], true);
        assert_eq!(relay.requests.lock().unwrap().len(), 1);
        assert_eq!(store.get_events("aw-stopwatch", None, None, None).unwrap().len(), 1);
        store.lock().unwrap();
    }

    mod enable_guards {
        use super::*;
        include!("companion_network_cases.rs");
    }
}
