use aw_datastore::Datastore;
use aw_egress::{EgressTransport, VerifiedPolicyV1};
use aw_models::{
    EgressDestinationV1, EgressPurposeV1, EgressUserPolicyV1, SignedEgressPolicyBundleV1,
    SyncEnvelopeV1, SyncRelayOperationV1, SyncRelayRequestV1, SyncRelayResponseV1,
};
use aw_server::sync_control::SyncControl;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};
#[derive(Clone, Default)]
pub(crate) struct Relay {
    pub(crate) objects: Arc<Mutex<BTreeMap<String, SyncEnvelopeV1>>>,
    pub(crate) requests: Arc<Mutex<Vec<SyncRelayOperationV1>>>,
    pub(crate) fail_after: Option<usize>,
    pub(crate) before_delete: Option<Arc<dyn Fn()+Send+Sync>>,
}
impl EgressTransport for Relay {
    fn send(
        &self,
        _: &EgressDestinationV1,
        _: &EgressPurposeV1,
        _: &[u8],
    ) -> Result<(), aw_models::EgressReasonCodeV1> {
        unreachable!()
    }
    fn request(
        &self,
        _: &EgressDestinationV1,
        _: &EgressPurposeV1,
        payload: &[u8],
    ) -> Result<Vec<u8>, aw_models::EgressReasonCodeV1> {
        let request: SyncRelayRequestV1 = serde_json::from_slice(payload).unwrap();
        request.validate().unwrap();
        let mut requests = self.requests.lock().unwrap();
        if self.fail_after.is_some_and(|max| requests.len() >= max) {
            return Err(aw_models::EgressReasonCodeV1::NetworkUnavailable);
        }
        if request.operation==SyncRelayOperationV1::DeleteSelectedBackup {
            if let Some(callback)=&self.before_delete{callback();}
        }
        requests.push(request.operation);
        let mut objects = self.objects.lock().unwrap();
        let response = match request.operation {
            SyncRelayOperationV1::PutIfAbsent => {
                let object = request.envelope.unwrap();
                let inserted = !objects.contains_key(&object.object_id);
                objects.entry(object.object_id.clone()).or_insert(object);
                SyncRelayResponseV1 {
                    schema_version: 1,
                    inserted: Some(inserted),
                    ..Default::default()
                }
            }
            SyncRelayOperationV1::Get => SyncRelayResponseV1 {
                schema_version: 1,
                envelope: objects.get(request.object_id.as_ref().unwrap()).cloned(),
                ..Default::default()
            },
            SyncRelayOperationV1::ListOpaqueHeads => {
                let mut page: Vec<_> = objects
                    .values()
                    .filter(|object| {
                        Some(&object.vault_id) == request.vault_id.as_ref()
                            && request
                                .cursor
                                .as_ref()
                                .is_none_or(|after| &object.object_id > after)
                    })
                    .take(request.limit.unwrap() as usize + 1)
                    .cloned()
                    .collect();
                let next_cursor = if page.len() > request.limit.unwrap() as usize {
                    page.pop();
                    page.last().map(|object| object.object_id.clone())
                } else {
                    None
                };
                SyncRelayResponseV1 {
                    schema_version: 1,
                    objects: page,
                    next_cursor,
                    ..Default::default()
                }
            }
            SyncRelayOperationV1::DeleteSelectedBackup => {
                let id = request.object_id.as_ref().unwrap();
                if objects
                    .get(id)
                    .is_some_and(|stored| Some(stored) != request.envelope.as_ref())
                {
                    return Err(aw_models::EgressReasonCodeV1::DestinationRejected);
                }
                SyncRelayResponseV1 {
                    schema_version: 1,
                    deleted: Some(objects.remove(id).is_some()),
                    ..Default::default()
                }
            }
            _ => panic!("Backup workflow must never acknowledge event tombstones"),
        };
        Ok(serde_json::to_vec(&response).unwrap())
    }
}

pub(crate) fn policy(store: &Datastore) -> VerifiedPolicyV1 {
    let key = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).unwrap();
    let mut bundle:SignedEgressPolicyBundleV1=serde_json::from_value(json!({"schema_version":1,"signer_key_id":"fixture","signature":[],
        "bundle":{"schema_version":1,"version":1,"hard_deny_version":1,"organization_rules":[],
            "destinations":[{"id":"sync-relay","status":"available","https_origin":"https://sync.example","allowed_purposes":["sync-object-v1"]}],
            "purposes":[{"id":"sync-object-v1","destination_id":"sync-relay","endpoint_path":"/v1/objects","retention_id":"ciphertext-only","retention_disclosure":"Ciphertext only","allowed_fields":["/schema_version","/operation","/object_id","/vault_id","/cursor","/limit","/envelope/*"]}]}})).unwrap();
    bundle.signature = key
        .sign(&aw_egress::policy_bundle_signing_bytes(&bundle).unwrap())
        .as_ref()
        .to_vec();
    let user = EgressUserPolicyV1 {
        schema_version: 1,
        user_rules: Vec::new(),
        safe_zone_patterns: Vec::new(),
        after_hours: None,
    };
    store.store_egress_policy_state(&bundle, &user).unwrap();
    store.set_egress_kill_switch(false).unwrap();
    aw_egress::verify_and_activate(
        &bundle,
        &user,
        &HashMap::from([("fixture".into(), key.public_key().as_ref().to_vec())]),
        None,
    )
    .unwrap()
}
pub(crate) fn source() -> (Datastore, Value, Value) {
    let store = Datastore::open_encrypted(":memory:".into(), "a".repeat(64)).unwrap();
    let control = SyncControl::new();
    let kit = control
        .invoke(&store, "create_sync_recovery_kit", json!({}))
        .unwrap();
    control
        .invoke(
            &store,
            "confirm_sync_recovery_saved",
            json!({"userConfirmed":true}),
        )
        .unwrap();
    store.set_key_value("settings.theme", "\"dark\"").unwrap();
    control
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let input = json!({"schema_version":1,"source_id":"local","context_id":store.get_sync_policy_context().unwrap().context_id});
    let listed = control
        .invoke(
            &store,
            "list_sync_backups",
            json!({"requestJson":input.to_string()}),
        )
        .unwrap();
    let mut selected = input;
    selected["selection"] = listed["versions"][0]["selection"].clone();
    (store, kit, selected)
}
pub(crate) fn request(operation: &str, source: &Value, selection: Option<Value>) -> String {
    json!({"schema_version":1,"context_id":source["context_id"],"operation":operation,"destination_id":"sync-relay","source_json":source.to_string(),"selection":selection}).to_string()
}

pub(crate) fn multipart_source() -> (Datastore, Value, Value) {
    let (store, kit, _) = source();
    store
        .create_bucket(&aw_models::Bucket {
            bid: None,
            id: "multipart-backup".into(),
            _type: "fixture".into(),
            client: "fixture".into(),
            hostname: "synthetic".into(),
            created: None,
            data: json!({"padding":"a".repeat(1_100_000)})
                .as_object()
                .unwrap()
                .clone(),
            metadata: Default::default(),
            events: None,
            last_updated: None,
        })
        .unwrap();
    let control = SyncControl::new();
    control
        .invoke(&store, "create_current_sync_snapshot", json!({}))
        .unwrap();
    let current = store.load_sync_snapshot().unwrap().unwrap();
    assert_eq!(current.envelopes.len(), 2);
    let input = json!({"schema_version":1,"source_id":"local","context_id":store.get_sync_policy_context().unwrap().context_id});
    let catalogue = control
        .invoke(
            &store,
            "list_sync_backups",
            json!({"requestJson":input.to_string()}),
        )
        .unwrap();
    let id = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        current.snapshot_id,
    );
    let row = catalogue["versions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["snapshot_id"] == id)
        .unwrap();
    let mut selected = input;
    selected["selection"] = row["selection"].clone();
    (store, kit, selected)
}
