use crate::{
    create_recovery_kit, create_vault_data_key, open_recovery_kit, unwrap_vault_data_key,
    generate_account_root_key, encrypt_chunk,
};
use aw_models::{RecoveryKitV1, SyncChunkHeaderV1, SYNC_SCHEMA_VERSION_V1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[test]
fn recovery_kit_roundtrips_keys_and_rejects_wrong_phrase_or_tampering() {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([21u8; 16]);
    let (vault_key, wrapped) = create_vault_data_key(&root, &vault_id, 2).unwrap();
    let (phrase, kit) = create_recovery_kit(&root, &wrapped).unwrap();
    let profile: serde_json::Value = serde_json::from_str(
        include_str!("../test-vectors/sync-recovery-v1.json"),
    )
    .unwrap();
    let profile = &profile["profile"];
    assert_eq!(kit.schema_version, profile["schema_version"]);
    assert_eq!(kit.kdf, profile["kdf"]);
    assert_eq!(kit.memory_kib, profile["memory_kib"]);
    assert_eq!(kit.iterations, profile["iterations"]);
    assert_eq!(kit.parallelism, profile["parallelism"]);
    assert_eq!(URL_SAFE_NO_PAD.decode(&kit.salt).unwrap().len(), profile["salt_bytes"]);
    assert_eq!(URL_SAFE_NO_PAD.decode(&kit.nonce).unwrap().len(), profile["nonce_bytes"]);
    assert!(!serde_json::to_string(&kit).unwrap().contains("SYNTHETIC_PRIVATE_KEY"));

    let recovered = open_recovery_kit(&kit, &phrase).unwrap();
    let restored_key = unwrap_vault_data_key(&recovered.account_root_key, &recovered.wrapped_vault_key).unwrap();
    let header = SyncChunkHeaderV1 {
        schema_version: SYNC_SCHEMA_VERSION_V1,
        object_id: URL_SAFE_NO_PAD.encode([22u8; 16]),
        vault_id,
        key_epoch: 2,
    };
    let encrypted = encrypt_chunk(&vault_key, &header, b"offline recovery test").unwrap();
    assert_eq!(
        &*crate::decrypt_chunk(&restored_key, &encrypted).unwrap(),
        b"offline recovery test"
    );
    let wrong_phrase = URL_SAFE_NO_PAD.encode([0xAA; 32]);
    assert!(open_recovery_kit(&kit, &wrong_phrase).is_err());

    let mut tampered = kit.clone();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&tampered.ciphertext).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    tampered.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    assert!(open_recovery_kit(&tampered, &phrase).is_err());

    let unsupported = RecoveryKitV1 {
        memory_kib: 1024,
        ..kit
    };
    assert!(open_recovery_kit(&unsupported, &phrase).is_err());
}
