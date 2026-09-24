use crate::crypto::{sync_chunk_aad, AccountRootKeyV1};
use crate::{
    create_vault_data_key, decrypt_chunk, encrypt_chunk, generate_account_root_key,
    unwrap_vault_data_key,
};
use aw_models::{SyncChunkHeaderV1, SYNC_MAX_CHUNK_BYTES};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use zeroize::Zeroizing;

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid vector hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vector() -> Value {
    serde_json::from_str(include_str!("../test-vectors/sync-crypto-v1.json")).unwrap()
}

#[test]
fn xchacha20_poly1305_matches_the_published_known_answer() {
    let vector = vector()["xchacha20_poly1305"].clone();
    let key: [u8; 32] = decode_hex(vector["key_hex"].as_str().unwrap()).try_into().unwrap();
    let nonce: [u8; 24] = decode_hex(vector["nonce_hex"].as_str().unwrap()).try_into().unwrap();
    let aad = decode_hex(vector["aad_hex"].as_str().unwrap());
    let plaintext = decode_hex(vector["plaintext_hex"].as_str().unwrap());
    let ciphertext = crate::crypto::seal_with_nonce(&key, &nonce, &aad, &plaintext).unwrap();
    assert_eq!(
        encode_hex(&ciphertext),
        vector["ciphertext_and_tag_hex"].as_str().unwrap()
    );
}

#[test]
fn sync_aad_matches_the_frozen_v1_layout() {
    let header = SyncChunkHeaderV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([1u8; 16]),
        vault_id: URL_SAFE_NO_PAD.encode([2u8; 16]),
        key_epoch: 1,
    };
    assert_eq!(
        encode_hex(&sync_chunk_aad(&header).unwrap()),
        concat!(
            "5065616b41637469766974792d53796e632d7631000000000101010101010101",
            "010101010101010101020202020202020202020202020202020000000000000001"
        )
    );
}

#[test]
fn random_vault_key_wrap_roundtrips_and_rejects_changes() {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([9u8; 16]);
    let (data_key, wrapped) = create_vault_data_key(&root, &vault_id, 3).unwrap();
    let unwrapped = unwrap_vault_data_key(&root, &wrapped).unwrap();
    let header = SyncChunkHeaderV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([4u8; 16]),
        vault_id: vault_id.clone(),
        key_epoch: 3,
    };
    let plaintext = b"synthetic activity secret";
    let envelope = encrypt_chunk(&data_key, &header, plaintext).unwrap();
    assert_eq!(&*decrypt_chunk(&unwrapped, &envelope).unwrap(), plaintext);

    let mut changed = wrapped.clone();
    changed.vault_id = URL_SAFE_NO_PAD.encode([8u8; 16]);
    assert!(unwrap_vault_data_key(&root, &changed).is_err());
    let wrong_root = AccountRootKeyV1::from_bytes(Zeroizing::new([7u8; 32]));
    assert!(unwrap_vault_data_key(&wrong_root, &wrapped).is_err());
}

#[test]
fn chunk_roundtrip_binds_header_key_epoch_and_authentication_tag() {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([3u8; 16]);
    let (key, _) = create_vault_data_key(&root, &vault_id, 2).unwrap();
    let header = SyncChunkHeaderV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([5u8; 16]),
        vault_id,
        key_epoch: 2,
    };
    let envelope = encrypt_chunk(&key, &header, b"fixed test payload").unwrap();
    assert_eq!(&*decrypt_chunk(&key, &envelope).unwrap(), b"fixed test payload");
    let (wrong_key, _) = create_vault_data_key(&root, &header.vault_id, header.key_epoch).unwrap();
    assert!(decrypt_chunk(&wrong_key, &envelope).is_err());
    let second_envelope = encrypt_chunk(&key, &header, b"fixed test payload").unwrap();
    assert_ne!(envelope.nonce, second_envelope.nonce);

    let mut changed_header = envelope.clone();
    changed_header.object_id = URL_SAFE_NO_PAD.encode([6u8; 16]);
    assert!(decrypt_chunk(&key, &changed_header).is_err());

    let mut changed_tag = envelope.clone();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&changed_tag.ciphertext).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    changed_tag.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    assert!(decrypt_chunk(&key, &changed_tag).is_err());

    let mut changed_epoch = envelope;
    changed_epoch.key_epoch += 1;
    assert!(decrypt_chunk(&key, &changed_epoch).is_err());
}

#[test]
fn chunk_boundaries_allow_empty_payload_and_reject_oversize_or_unknown_version() {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([4u8; 16]);
    let (key, _) = create_vault_data_key(&root, &vault_id, 1).unwrap();
    let header = SyncChunkHeaderV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([5u8; 16]),
        vault_id,
        key_epoch: 1,
    };
    let empty = encrypt_chunk(&key, &header, b"").unwrap();
    assert_eq!(&*decrypt_chunk(&key, &empty).unwrap(), b"");
    let maximum = vec![42; SYNC_MAX_CHUNK_BYTES];
    let maximum_envelope = encrypt_chunk(&key, &header, &maximum).unwrap();
    assert_eq!(
        decrypt_chunk(&key, &maximum_envelope).unwrap().as_slice(),
        maximum.as_slice()
    );
    assert!(encrypt_chunk(&key, &header, &vec![0; SYNC_MAX_CHUNK_BYTES + 1]).is_err());

    let mut unknown = empty;
    unknown.schema_version = 2;
    assert!(decrypt_chunk(&key, &unknown).is_err());
    let mut malformed = maximum_envelope;
    malformed.nonce = "invalid!".into();
    assert!(decrypt_chunk(&key, &malformed).is_err());
}
