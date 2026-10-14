use aw_models::SyncRelayOperationV1;
use aw_sync_e2ee::{
    create_vault_data_key, encrypt_snapshot, generate_account_root_key, SnapshotDeletionProofV1,
    SyncHttpObjectStoreV1, SyncObjectStoreErrorV1, SyncRelayRequestV1, SyncRelayResponseV1,
    SyncRelayTransportV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::sync::{Arc, Mutex};
#[derive(Clone)]
struct Provider {
    calls: Arc<Mutex<Vec<SyncRelayRequestV1>>>,
    actual: Arc<Mutex<Option<aw_models::SyncEnvelopeV1>>>,
    mode: u8,
}
impl SyncRelayTransportV1 for Provider {
    fn request(
        &self,
        _: &str,
        _: &str,
        request: &SyncRelayRequestV1,
    ) -> Result<SyncRelayResponseV1, SyncObjectStoreErrorV1> {
        self.calls.lock().unwrap().push(request.clone());
        assert_eq!(
            request.operation,
            SyncRelayOperationV1::DeleteSelectedBackup
        );
        request.validate().unwrap();
        if self.mode == 1 {
            return Err(SyncObjectStoreErrorV1::TransportUnavailable);
        }
        if self.mode == 2 {
            return Ok(SyncRelayResponseV1 {
                schema_version: 1,
                ..Default::default()
            });
        }
        if self.mode == 3 {
            return Ok(SyncRelayResponseV1 {
                schema_version: 1,
                deleted: Some(true),
                inserted: Some(true),
                ..Default::default()
            });
        }
        let mut actual = self.actual.lock().unwrap();
        if actual
            .as_ref()
            .is_some_and(|actual| Some(actual) != request.envelope.as_ref())
        {
            return Err(SyncObjectStoreErrorV1::ObjectConflict);
        }
        Ok(SyncRelayResponseV1 {
            schema_version: 1,
            deleted: Some(actual.take().is_some()),
            ..Default::default()
        })
    }
}
fn fixture() -> (
    aw_sync_e2ee::VaultDataKeyV1,
    aw_sync_e2ee::EncryptedSyncSnapshotV1,
) {
    let key = create_vault_data_key(
        &generate_account_root_key().unwrap(),
        &URL_SAFE_NO_PAD.encode([1; 16]),
        u64::MAX,
    )
    .unwrap()
    .0;
    let snapshot = encrypt_snapshot(&key, b"authenticated backup fixture").unwrap();
    (key, snapshot)
}
#[test]
fn selected_backup_adapter_compares_expected_ciphertext_and_observes_missing_without_event_fallback(
) {
    let (key, snapshot) = fixture();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let actual = Arc::new(Mutex::new(Some(snapshot.envelopes[0].clone())));
    let remote = SyncHttpObjectStoreV1::new(
        "signed-relay".into(),
        "sync-object-v1".into(),
        Provider {
            calls: calls.clone(),
            actual: actual.clone(),
            mode: 0,
        },
    )
    .unwrap();
    assert!(remote
        .delete_selected_backup(&proof, &snapshot.envelopes[0])
        .unwrap());
    assert!(!remote
        .delete_selected_backup(&proof, &snapshot.envelopes[0])
        .unwrap());
    assert_eq!(calls.lock().unwrap().len(), 2);
    let mut changed = snapshot.envelopes[0].clone();
    changed.nonce = URL_SAFE_NO_PAD.encode([9; 24]);
    *actual.lock().unwrap() = Some(changed.clone());
    assert_eq!(
        remote.delete_selected_backup(&proof, &snapshot.envelopes[0]),
        Err(SyncObjectStoreErrorV1::ObjectConflict)
    );
    assert_eq!(*actual.lock().unwrap(), Some(changed));
}
#[test]
fn selected_backup_adapter_rejects_unverified_objects_before_transport_and_never_guesses_unsupported_success(
) {
    let (key, snapshot) = fixture();
    let proof = SnapshotDeletionProofV1::authenticate(&key, &snapshot).unwrap();
    for mode in [1, 2, 3] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let actual = Arc::new(Mutex::new(Some(snapshot.envelopes[0].clone())));
        let remote = SyncHttpObjectStoreV1::new(
            "signed-relay".into(),
            "sync-object-v1".into(),
            Provider {
                calls: calls.clone(),
                actual: actual.clone(),
                mode,
            },
        )
        .unwrap();
        let mut forged = snapshot.envelopes[0].clone();
        forged.nonce = URL_SAFE_NO_PAD.encode([9; 24]);
        assert!(remote.delete_selected_backup(&proof, &forged).is_err());
        assert!(calls.lock().unwrap().is_empty());
        assert!(remote
            .delete_selected_backup(&proof, &snapshot.envelopes[0])
            .is_err());
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(*actual.lock().unwrap(), Some(snapshot.envelopes[0].clone()));
    }
}
