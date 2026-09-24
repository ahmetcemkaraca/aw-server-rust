use crate::{create_vault_data_key, encrypt_chunk, generate_account_root_key};
use crate::SyncObjectStoreV1;
use aw_models::{SyncChunkHeaderV1, SYNC_SCHEMA_VERSION_V1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::fs;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use crate::{
    SyncHttpObjectStoreV1, SyncObjectStoreErrorV1, SyncRelayOperationV1,
    SyncRelayRequestV1, SyncRelayResponseV1, SyncRelayTransportV1,
    SyncTombstoneAckProofV1, SyncTombstoneDeletionPermitV1,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn root(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "peakactivity-sync-store-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ))
}

fn envelope(vault: [u8; 16], object: [u8; 16], text: &[u8]) -> aw_models::SyncEnvelopeV1 {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode(vault);
    let (key, _) = create_vault_data_key(&root, &vault_id, 3).unwrap();
    let header = SyncChunkHeaderV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        object_id: URL_SAFE_NO_PAD.encode(object),
        vault_id,
        key_epoch: 3,
    };
    encrypt_chunk(&key, &header, text).unwrap()
}

#[test]
fn folder_store_is_immutable_opaque_and_tombstone_gated() {
    let path = root("objects");
    let first = envelope([0x11; 16], [0x22; 16], b"private-window-title-and-file-path");
    let second = envelope([0x33; 16], [0x44; 16], b"other-device-event");
    let store = super::FolderSyncObjectStoreV1::open(&path).unwrap();

    assert!(store.put_if_absent(&first).unwrap());
    assert!(!store.put_if_absent(&first).unwrap());
    assert_eq!(store.get(&first.object_id).unwrap(), Some(first.clone()));
    let heads = store.list_opaque_heads(&first.vault_id).unwrap();
    assert_eq!(heads, vec![first.clone()]);
    assert!(store.put_if_absent(&second).unwrap());
    assert_eq!(store.list_opaque_heads(&second.vault_id).unwrap(), vec![second.clone()]);

    let serialized = fs::read_to_string(path.join(format!("{}.json", first.object_id))).unwrap();
    assert!(!serialized.contains("private-window-title"));
    let active_devices = vec![URL_SAFE_NO_PAD.encode([0x51; 16]), URL_SAFE_NO_PAD.encode([0x52; 16])];
    let proof = SyncTombstoneAckProofV1::new(active_devices.clone(), vec![active_devices[0].clone()]);
    assert!(SyncTombstoneDeletionPermitV1::authorize(&first.object_id, &[proof]).is_err());
    let proof = SyncTombstoneAckProofV1::new(active_devices.clone(), active_devices.clone());
    let permit = SyncTombstoneDeletionPermitV1::authorize(&first.object_id, &[proof]).unwrap();
    assert!(store.delete_after_tombstone(&permit).unwrap());
    assert!(store.get(&first.object_id).unwrap().is_none());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn folder_store_rejects_object_id_conflicts_and_corrupted_files() {
    let path = root("conflict");
    let first = envelope([0x51; 16], [0x62; 16], b"content-one");
    let store = super::FolderSyncObjectStoreV1::open(&path).unwrap();
    assert!(store.put_if_absent(&first).unwrap());

    let mut conflicting = envelope([0x51; 16], [0x62; 16], b"content-two");
    conflicting.object_id = first.object_id.clone();
    assert!(matches!(
        store.put_if_absent(&conflicting),
        Err(super::SyncObjectStoreErrorV1::ObjectConflict)
    ));

    fs::write(path.join(format!("{}.json", first.object_id)), b"not-an-envelope").unwrap();
    assert!(matches!(
        store.get(&first.object_id),
        Err(super::SyncObjectStoreErrorV1::CorruptObject)
    ));
    fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
fn folder_store_refuses_a_symlink_root() {
    let outside = root("outside");
    let linked = root("linked");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, &linked).unwrap();
    assert!(super::FolderSyncObjectStoreV1::open(&linked).is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    fs::remove_file(linked).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[derive(Clone)]
struct FakeRelayTransport {
    requests: Arc<Mutex<Vec<(String, String, SyncRelayRequestV1)>>>,
    objects: Arc<Mutex<BTreeMap<String, aw_models::SyncEnvelopeV1>>>,
}

impl SyncRelayTransportV1 for FakeRelayTransport {
    fn request(
        &self,
        destination_id: &str,
        purpose_id: &str,
        request: &SyncRelayRequestV1,
    ) -> Result<SyncRelayResponseV1, SyncObjectStoreErrorV1> {
        self.requests.lock().unwrap().push((destination_id.into(), purpose_id.into(), request.clone()));
        let mut response = SyncRelayResponseV1 { schema_version: 1, ..Default::default() };
        let mut objects = self.objects.lock().unwrap();
        match request.operation {
            SyncRelayOperationV1::PutIfAbsent => {
                let envelope = request.envelope.clone().ok_or(SyncObjectStoreErrorV1::InvalidEnvelope)?;
                if let Some(existing) = objects.get(&envelope.object_id) {
                    if existing != &envelope { return Err(SyncObjectStoreErrorV1::ObjectConflict); }
                    response.inserted = Some(false);
                } else {
                    objects.insert(envelope.object_id.clone(), envelope);
                    response.inserted = Some(true);
                }
            }
            SyncRelayOperationV1::Get => {
                response.envelope = request.object_id.as_ref().and_then(|id| objects.get(id).cloned());
            }
            SyncRelayOperationV1::ListOpaqueHeads => {
                let vault_id = request.vault_id.as_deref().ok_or(SyncObjectStoreErrorV1::InvalidEnvelope)?;
                let cursor = request.cursor.as_deref();
                let limit = request.limit.unwrap_or(1) as usize;
                let page = objects.values()
                    .filter(|item| item.vault_id == vault_id && cursor.is_none_or(|after| item.object_id.as_str() > after))
                    .take(limit + 1)
                    .cloned()
                    .collect::<Vec<_>>();
                let more = page.len() > limit;
                response.objects = page.into_iter().take(limit).collect();
                if more { response.next_cursor = response.objects.last().map(|item| item.object_id.clone()); }
            }
            SyncRelayOperationV1::DeleteAfterTombstone => {
                response.deleted = Some(request.object_id.as_ref().is_some_and(|id| objects.remove(id).is_some()));
            }
        }
        Ok(response)
    }
}

#[test]
fn http_adapter_uses_only_signed_ids_and_preserves_the_same_envelope() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let transport = FakeRelayTransport {
        requests: requests.clone(),
        objects: Arc::new(Mutex::new(BTreeMap::new())),
    };
    let store = SyncHttpObjectStoreV1::new("signed-sync-relay".into(), "sync-object-v1".into(), transport).unwrap();
    let envelope = envelope([0xA1; 16], [0xA2; 16], b"private-activity-value");
    assert!(store.put_if_absent(&envelope).unwrap());
    assert!(!store.put_if_absent(&envelope).unwrap());
    assert_eq!(store.get(&envelope.object_id).unwrap(), Some(envelope.clone()));
    assert_eq!(store.list_opaque_heads(&envelope.vault_id).unwrap(), vec![envelope.clone()]);
    let active = vec![URL_SAFE_NO_PAD.encode([0xA3; 16])];
    let proof = SyncTombstoneAckProofV1::new(active.clone(), active);
    let permit = SyncTombstoneDeletionPermitV1::authorize(&envelope.object_id, &[proof]).unwrap();
    assert!(store.delete_after_tombstone(&permit).unwrap());

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert!(requests.iter().all(|(destination, purpose, _)| {
        destination == "signed-sync-relay" && purpose == "sync-object-v1"
    }));
    assert_eq!(requests[0].2.envelope.as_ref(), Some(&envelope));
    assert!(!serde_json::to_string(&requests[0].2).unwrap().contains("private-activity-value"));
    assert!(SyncHttpObjectStoreV1::new("https://relay.example".into(), "sync-object-v1".into(), FakeRelayTransport {
        requests: Arc::new(Mutex::new(Vec::new())),
        objects: Arc::new(Mutex::new(BTreeMap::new())),
    }).is_err());
}

#[test]
fn http_object_listing_follows_opaque_cursor_pages_without_duplicates() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let store = SyncHttpObjectStoreV1::new("sync-relay".into(), "sync-object-v1".into(), FakeRelayTransport {
        requests: requests.clone(),
        objects: Arc::new(Mutex::new(BTreeMap::new())),
    }).unwrap();
    let mut expected = (1..=17).map(|id| envelope([0xB1; 16], [id; 16], &[id])).collect::<Vec<_>>();
    expected.sort_by(|left, right| left.object_id.cmp(&right.object_id));
    for object in &expected { assert!(store.put_if_absent(object).unwrap()); }

    let listed = store.list_opaque_heads(&expected[0].vault_id).unwrap();
    assert_eq!(listed, expected);
    let requests = requests.lock().unwrap();
    let list_requests = requests.iter().filter(|(_, _, request)| request.operation == SyncRelayOperationV1::ListOpaqueHeads).collect::<Vec<_>>();
    assert_eq!(list_requests.len(), 2);
    assert_eq!(list_requests[0].2.cursor, None);
    assert_eq!(list_requests[1].2.cursor.as_deref(), Some(expected[15].object_id.as_str()));
    assert!(list_requests.iter().all(|(_, _, request)| request.limit == Some(16)));
}

#[test]
fn relay_metadata_vector_contains_no_synthetic_activity_markers() {
    let vector: serde_json::Value = serde_json::from_str(include_str!("../test-vectors/sync-relay-v1.json")).unwrap();
    let request: SyncRelayRequestV1 = serde_json::from_value(vector["request"].clone()).unwrap();
    request.validate().unwrap();
    let serialized = serde_json::to_string(&request).unwrap();
    for marker in vector["private_markers"].as_array().unwrap() {
        assert!(!serialized.contains(marker.as_str().unwrap()));
    }
    let response: SyncRelayResponseV1 = serde_json::from_value(vector["response"].clone()).unwrap();
    assert_eq!(response.inserted, Some(true));
    assert_eq!(response.objects.len(), 0);
}
