use crate::{
    create_vault_data_key, decrypt_chunk, encrypt_chunk, generate_account_root_key,
    reencrypt_snapshot_chunks, rotate_account_and_vault_key, unwrap_vault_data_key,
};
use aw_models::{SyncChunkHeaderV1, SYNC_SCHEMA_VERSION_V1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[test]
fn lost_device_rotation_changes_root_and_epoch_and_reencrypts_snapshot_chunks() {
    let old_root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([0x41; 16]);
    let (old_key, old_wrapped) = create_vault_data_key(&old_root, &vault_id, 4).unwrap();
    let old_header = SyncChunkHeaderV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        object_id: URL_SAFE_NO_PAD.encode([0x42; 16]),
        vault_id,
        key_epoch: 4,
    };
    let old_envelope = encrypt_chunk(&old_key, &old_header, b"encrypted snapshot").unwrap();

    let (new_root, new_key, new_wrapped) =
        rotate_account_and_vault_key(&old_root, &old_wrapped).unwrap();
    assert_eq!(new_wrapped.key_epoch, 5);
    assert_ne!(old_root.as_bytes(), new_root.as_bytes());
    assert!(unwrap_vault_data_key(&old_root, &new_wrapped).is_err());
    assert!(unwrap_vault_data_key(&new_root, &new_wrapped).is_ok());

    let new_snapshot = reencrypt_snapshot_chunks(&old_key, &new_key, &[old_envelope.clone()]).unwrap();
    assert_eq!(new_snapshot.len(), 1);
    assert_ne!(new_snapshot[0].object_id, old_envelope.object_id);
    assert_eq!(new_snapshot[0].key_epoch, 5);
    assert_eq!(&*decrypt_chunk(&new_key, &new_snapshot[0]).unwrap(), b"encrypted snapshot");
    assert!(decrypt_chunk(&old_key, &new_snapshot[0]).is_err());
}
