use crate::{
    create_vault_data_key, decrypt_snapshot, encrypt_snapshot, generate_account_root_key,
    inspect_snapshot_chunk,
    reencrypt_snapshot_chunks, rotate_account_and_vault_key, EncryptedSyncSnapshotV1,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[test]
fn encrypted_snapshot_chunks_are_complete_ordered_and_rekeyable() {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([0x71; 16]);
    let (old_key, old_wrapped) = create_vault_data_key(&root, &vault_id, 1).unwrap();
    let mut plaintext = vec![0xA5; 1_100_000];
    plaintext.extend_from_slice(b"private-activity-marker");
    let old_snapshot = encrypt_snapshot(&old_key, &plaintext).unwrap();
    assert!(!serde_json::to_string(&old_snapshot).unwrap().contains("private-activity-marker"));
    assert_eq!(old_snapshot.envelopes.len(), 2);
    for (index, envelope) in old_snapshot.envelopes.iter().enumerate() {
        let header = inspect_snapshot_chunk(&old_key, envelope).unwrap();
        assert_eq!(header.snapshot_id, old_snapshot.snapshot_id);
        assert_eq!(header.index, index as u32);
        assert_eq!(header.count, old_snapshot.envelopes.len() as u32);
    }
    assert_eq!(decrypt_snapshot(&old_key, &old_snapshot).unwrap().as_slice(), plaintext.as_slice());

    let (new_root, new_key, _) = rotate_account_and_vault_key(&root, &old_wrapped).unwrap();
    let new_envelopes = reencrypt_snapshot_chunks(&old_key, &new_key, &old_snapshot.envelopes).unwrap();
    let new_snapshot = EncryptedSyncSnapshotV1 {
        schema_version: old_snapshot.schema_version,
        snapshot_id: old_snapshot.snapshot_id.clone(),
        envelopes: new_envelopes,
    };
    assert_eq!(decrypt_snapshot(&new_key, &new_snapshot).unwrap().as_slice(), plaintext.as_slice());
    assert!(decrypt_snapshot(&old_key, &new_snapshot).is_err());

    let mut reordered = new_snapshot;
    reordered.envelopes.swap(0, 1);
    assert!(decrypt_snapshot(&new_key, &reordered).is_err());

    let mut tampered = old_snapshot.clone();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&tampered.envelopes[0].ciphertext).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    tampered.envelopes[0].ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    assert!(decrypt_snapshot(&old_key, &tampered).is_err());
    let mut incomplete = old_snapshot;
    incomplete.envelopes.pop();
    assert!(decrypt_snapshot(&old_key, &incomplete).is_err());
    assert_ne!(new_root.as_bytes(), root.as_bytes());
}
