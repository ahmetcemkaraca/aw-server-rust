use std::collections::BTreeMap;

use crate::merge::{
    create_event_correction, create_event_tombstone, create_event_upsert, decode_sync_data_field_v1,
    encode_sync_data_field_v1, merge_operations,
    pending_tombstone_ack_device_ids,
    tombstone_collectible, ManifestDecisionV1, MergeErrorV1, SyncHeadV1, SyncManifestV1,
    SyncOperationV1, SyncTombstoneAckV1,
};
use crate::{
    create_vault_data_key, decrypt_manifest, encrypt_manifest, generate_account_root_key,
};
use aw_models::{Event, SyncBucketDescriptorV1, SyncChunkHeaderV1, SyncOperationKindV1};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::DeviceIdentityV1;

fn bucket_descriptor() -> SyncBucketDescriptorV1 {
    SyncBucketDescriptorV1 {
        bucket_type: "app".into(),
        client: "PeakActivity".into(),
        data: BTreeMap::new(),
    }
}

fn signing_identity(device: u8) -> DeviceIdentityV1 {
    DeviceIdentityV1::from_bytes(
        [device; 16],
        Zeroizing::new([device.wrapping_add(1); 32]),
        Zeroizing::new([device.wrapping_add(2); 32]),
    )
}

fn event_op(
    device: u8,
    counter: u64,
    kind: SyncOperationKindV1,
    fields: &[(&str, Value)],
) -> SyncOperationV1 {
    let bucket_descriptor = (kind == SyncOperationKindV1::Upsert).then(bucket_descriptor);
    SyncOperationV1 {
        schema_version: 1,
        device_id: URL_SAFE_NO_PAD.encode([device; 16]),
        counter,
        origin_device_id: URL_SAFE_NO_PAD.encode([9u8; 16]),
        local_event_id: Some(42),
        sync_bucket_id: Some(URL_SAFE_NO_PAD.encode([0x66u8; 16])),
        bucket_descriptor,
        kind,
        policy_version: None,
        fields: fields.iter().map(|(key, value)| ((*key).into(), value.clone())).collect(),
    }
}

#[test]
fn local_event_operations_preserve_origin_and_correction_scope() {
    let mut event: Event = serde_json::from_value(json!({
        "id": 42,
        "timestamp": "2026-09-23T12:00:00Z",
        "duration": 7.0,
        "data": {"app":"Editor","title":"SYNTHETIC_TITLE"}
    }))
    .unwrap();
    event.data.insert("timestamp".into(), json!("user data value"));
    let unusual_key = "data:\nprivate";
    event.data.insert(unusual_key.into(), json!("private key name"));
    let device = [1u8; 16];
    let origin = device;
    let upsert = create_event_upsert(device, 1, [0x66; 16], bucket_descriptor(), &event).unwrap();
    assert_eq!(upsert.origin_device_id, URL_SAFE_NO_PAD.encode(origin));
    assert_eq!(upsert.local_event_id, Some(42));
    assert_eq!(upsert.sync_bucket_id, Some(URL_SAFE_NO_PAD.encode([0x66; 16])));
    assert_eq!(upsert.bucket_descriptor, Some(bucket_descriptor()));
    assert_eq!(upsert.fields["timestamp"], json!("2026-09-23T12:00:00+00:00"));
    assert_eq!(upsert.fields["duration_ns"], json!(7_000_000_000i64));
    assert_eq!(upsert.fields["data:title"], json!("SYNTHETIC_TITLE"));
    assert_eq!(upsert.fields["data:timestamp"], json!("user data value"));

    assert_eq!(encode_sync_data_field_v1("timestamp"), "data:timestamp");
    let encoded = encode_sync_data_field_v1(unusual_key);
    assert!(!encoded.chars().any(char::is_control));
    assert_eq!(decode_sync_data_field_v1(&encoded).as_deref(), Some(unusual_key));
    assert_eq!(upsert.fields[&encoded], json!("private key name"));

    let correction = create_event_correction(
        [2u8; 16],
        2,
        origin,
        42,
        [0x66; 16],
        BTreeMap::from([("data:title".into(), json!("Corrected"))]),
    )
    .unwrap();
    assert_eq!(correction.kind, SyncOperationKindV1::Correction);
    assert_eq!(correction.fields.len(), 1);
    assert!(correction.fields.contains_key("data:title"));
    let merged = merge_operations(&[upsert.clone()], &[correction.clone()]).unwrap();
    assert_eq!(merged.events[0].sync_bucket_id, URL_SAFE_NO_PAD.encode([0x66; 16]));

    let tombstone = create_event_tombstone([2u8; 16], 3, origin, 42, [0x66; 16]).unwrap();
    assert_eq!(tombstone.kind, SyncOperationKindV1::Tombstone);
    assert!(tombstone.fields.is_empty());
}

#[test]
fn merge_history_can_exceed_the_per_manifest_operation_limit() {
    let operations = (1..=10_001)
        .map(|counter| event_op(1, counter, SyncOperationKindV1::Upsert, &[("title", json!("same"))]))
        .collect::<Vec<_>>();
    assert!(SyncManifestV1::new_signed(&signing_identity(1), [0x77; 16], 1, 1, [0; 32], operations.clone()).is_err());

    let merged = merge_operations(&[], &operations).unwrap();

    assert_eq!(merged.operations.len(), 10_001);
    assert_eq!(merged.events.len(), 1);
}

#[test]
fn counters_event_ids_and_revisions_fit_sqlite_integer_storage() {
    let too_large = i64::MAX as u64 + 1;
    assert!(create_event_correction(
        [1u8; 16],
        too_large,
        [1u8; 16],
        42,
        [0x66; 16],
        BTreeMap::from([("app".into(), json!("Editor"))]),
    )
    .is_err());
    assert!(create_event_correction(
        [1u8; 16],
        1,
        [1u8; 16],
        too_large,
        [0x66; 16],
        BTreeMap::from([("app".into(), json!("Editor"))]),
    )
    .is_err());
    let writer = signing_identity(1);
    assert!(SyncManifestV1::new_signed(&writer, [0x77; 16], 1, too_large, [0; 32], Vec::new()).is_err());
}

#[test]
fn one_origin_event_cannot_be_assigned_to_two_sync_buckets() {
    let upsert = event_op(1, 1, SyncOperationKindV1::Upsert, &[("app", json!("Editor"))]);
    let mut correction = event_op(2, 1, SyncOperationKindV1::Correction, &[("app", json!("Other"))]);
    correction.sync_bucket_id = Some(URL_SAFE_NO_PAD.encode([0x67; 16]));

    assert!(matches!(
        merge_operations(&[upsert], &[correction]),
        Err(MergeErrorV1::BucketIdentityFork)
    ));
}

#[test]
fn one_sync_bucket_cannot_change_its_descriptor() {
    let first = event_op(1, 1, SyncOperationKindV1::Upsert, &[("app", json!("Editor"))]);
    let mut changed = event_op(2, 1, SyncOperationKindV1::Upsert, &[("app", json!("Editor"))]);
    changed.bucket_descriptor.as_mut().unwrap().client = "OtherClient".into();

    assert!(matches!(
        merge_operations(&[first], &[changed]),
        Err(MergeErrorV1::BucketDescriptorFork)
    ));
}

fn manifest_outcome(result: Result<ManifestDecisionV1, MergeErrorV1>) -> &'static str {
    match result {
        Ok(ManifestDecisionV1::Advanced(_)) => "advanced",
        Ok(ManifestDecisionV1::Duplicate) => "duplicate",
        Err(MergeErrorV1::RevisionFork) => "fork",
        Err(MergeErrorV1::Rollback) => "rollback",
        Err(MergeErrorV1::InvalidAncestry) => "invalid_ancestry",
        Err(MergeErrorV1::RevisionGap) => "revision_gap",
        Err(_) => "invalid",
    }
}

#[test]
fn shared_merge_vectors_cover_replay_clock_skew_tombstones_and_policy_conflicts() {
    let vectors: Value =
        serde_json::from_str(include_str!("../test-vectors/sync-merge-v1.json")).unwrap();
    let manifest = &vectors["manifest"];
    let parent_hash: [u8; 32] = URL_SAFE_NO_PAD
        .decode(manifest["parent_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let manifest_ops: Vec<SyncOperationV1> =
        serde_json::from_value(manifest["operations"].clone()).unwrap();
    let writer = signing_identity(1);
    let vault_id = [0x17; 16];
    let manifest = SyncManifestV1::new_signed(
        &writer,
        vault_id,
        manifest["key_epoch"].as_u64().unwrap(),
        manifest["revision"].as_u64().unwrap(),
        parent_hash,
        manifest_ops,
    )
    .unwrap();
    assert_eq!(manifest.head_hash, vectors["manifest"]["head_hash"]);
    assert_eq!(manifest.signature, vectors["manifest"]["signature"].as_str().unwrap());
    assert_eq!(
        writer.public_identity().ed25519_public_key,
        vectors["manifest"]["writer_signing_public_key"].as_str().unwrap()
    );
    manifest.verify_signature(&writer.public_identity(), &vault_id).unwrap();
    assert!(manifest.verify_signature(&writer.public_identity(), &[0x18; 16]).is_err());

    for (name, vector) in vectors["cases"].as_object().unwrap() {
        let operations = vector["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| serde_json::from_value::<SyncOperationV1>(value.clone()).unwrap())
            .collect::<Vec<_>>();
        let merged = merge_operations(&operations, &operations).unwrap();
        assert_eq!(merged.operations.len(), vector["expected"]["operation_count"]);

        match name.as_str() {
            "clock_skew_duplicate_and_concurrent_fields" => {
                let expected_fields: BTreeMap<String, Value> =
                    serde_json::from_value(vector["expected"]["fields"].clone()).unwrap();
                assert_eq!(merged.events.len(), 1);
                assert!(merged.events[0].fields == expected_fields);
                assert_eq!(merged.events[0].deleted, vector["expected"]["deleted"]);
                let mut actual = merged.conflicts.iter().map(|item| item.field.clone()).collect::<Vec<_>>();
                actual.sort();
                let expected: Vec<String> = serde_json::from_value(
                    vector["expected"]["conflict_fields"].clone(),
                )
                .unwrap();
                assert_eq!(actual, expected);
            }
            "tombstone_equal_counter" => {
                assert_eq!(merged.events.len(), 1);
                assert!(merged.events[0].deleted);
                assert!(merged.events[0].fields.is_empty());
                assert_eq!(merged.conflicts[0].field, vector["expected"]["tombstone_wins"]);
                assert!(merged.conflicts[0].winner_is_tombstone);
            }
            "same_device_sequential_edit" => {
                let expected_fields: BTreeMap<String, Value> =
                    serde_json::from_value(vector["expected"]["fields"].clone()).unwrap();
                assert!(merged.events[0].fields == expected_fields);
                assert!(merged.conflicts.is_empty());
            }
            "policy_change_requires_local_choice" => {
                assert!(merged.events.is_empty());
                let pending = merged.pending_policy_conflict.unwrap();
                let expected_devices: Vec<String> = serde_json::from_value(
                    vector["expected"]["policy_devices"].clone(),
                )
                .unwrap();
                let expected_versions: Vec<u64> = serde_json::from_value(
                    vector["expected"]["policy_versions"].clone(),
                )
                .unwrap();
                assert_eq!(pending.devices, expected_devices);
                assert_eq!(pending.versions, expected_versions);
                let metadata = serde_json::to_string(&pending).unwrap();
                assert!(!metadata.contains("recording"));
                assert!(!metadata.contains("true"));
                assert!(!metadata.contains("false"));
            }
            _ => panic!("unknown merge vector case"),
        }

        let mut reversed = operations.clone();
        reversed.reverse();
        let reverse_merge = merge_operations(&[], &reversed).unwrap();
        assert!(merged.operations == reverse_merge.operations);
        assert!(merged.events == reverse_merge.events);
    }
}

#[test]
fn encrypted_manifest_keeps_event_fields_inside_the_authenticated_chunk() {
    let root = generate_account_root_key().unwrap();
    let vault_id = URL_SAFE_NO_PAD.encode([17u8; 16]);
    let (key, _) = create_vault_data_key(&root, &vault_id, 1).unwrap();
    let header = SyncChunkHeaderV1 {
        schema_version: 1,
        object_id: URL_SAFE_NO_PAD.encode([18u8; 16]),
        vault_id,
        key_epoch: 1,
    };
    let writer = signing_identity(1);
    let manifest = SyncManifestV1::new_signed(
        &writer,
        [17u8; 16],
        1,
        1,
        [0u8; 32],
        vec![event_op(
            1,
            1,
            SyncOperationKindV1::Upsert,
            &[("title", json!("SYNTHETIC_PRIVATE_EVENT_TITLE"))],
        )],
    )
    .unwrap();
    let envelope = encrypt_manifest(&key, &header, &manifest).unwrap();
    let visible = serde_json::to_string(&envelope).unwrap();
    assert!(!visible.contains("SYNTHETIC_PRIVATE_EVENT_TITLE"));
    let decrypted = decrypt_manifest(&key, &envelope).unwrap();
    assert_eq!(decrypted.revision, manifest.revision);
    assert_eq!(decrypted.head_hash, manifest.head_hash);
    assert_eq!(decrypted.operations[0].fields["title"], json!("SYNTHETIC_PRIVATE_EVENT_TITLE"));
    decrypted.verify_signature(&writer.public_identity(), &[17u8; 16]).unwrap();
    let mut altered_signature = decrypted.clone();
    altered_signature.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(altered_signature.verify_signature(&writer.public_identity(), &[17u8; 16]).is_err());

    let mut tampered = envelope;
    tampered.ciphertext = URL_SAFE_NO_PAD.encode([0u8; 160]);
    assert!(decrypt_manifest(&key, &tampered).is_err());
}

#[test]
fn reusing_a_device_counter_for_different_content_is_rejected() {
    let first = event_op(1, 7, SyncOperationKindV1::Correction, &[("app", json!("one"))]);
    let fork = event_op(1, 7, SyncOperationKindV1::Correction, &[("app", json!("two"))]);
    assert!(matches!(
        merge_operations(&[first], &[fork]),
        Err(MergeErrorV1::OperationFork)
    ));
}

#[test]
fn tombstones_wait_for_every_active_device_but_removed_devices_no_longer_block_collection() {
    let first = URL_SAFE_NO_PAD.encode([1u8; 16]);
    let second = URL_SAFE_NO_PAD.encode([2u8; 16]);
    let removed = URL_SAFE_NO_PAD.encode([3u8; 16]);
    assert!(!tombstone_collectible(&[first.clone(), second.clone()], &[first.clone()]).unwrap());
    assert!(tombstone_collectible(&[first.clone(), second.clone()], &[first, second, removed]).unwrap());
}

#[test]
fn pending_tombstone_ack_device_ids_lists_only_active_devices_without_acknowledgements() {
    let active = [[1u8; 16], [2u8; 16], [3u8; 16]];
    let acknowledged = [[1u8; 16], [3u8; 16]];

    assert_eq!(pending_tombstone_ack_device_ids(&active, &acknowledged), vec![[2u8; 16]]);
    assert!(pending_tombstone_ack_device_ids(&active, &active).is_empty());
}

#[test]
fn manifest_head_rejects_replay_rollback_fork_gap_and_wrong_parent() {
    let vector: Value =
        serde_json::from_str(include_str!("../test-vectors/sync-merge-v1.json")).unwrap();
    let expected = &vector["manifest_decisions"];
    let operation = event_op(1, 1, SyncOperationKindV1::Upsert, &[("app", json!("Editor"))]);
    let genesis = SyncHeadV1::genesis();
    let writer = signing_identity(1);
    let first = SyncManifestV1::new_signed(&writer, [0x77; 16], 1, 1, [0; 32], vec![operation.clone()]).unwrap();
    let decision = first.advance(&genesis).unwrap();
    assert_eq!(manifest_outcome(Ok(decision)), expected["first_revision"]);
    let decision = first.advance(&genesis).unwrap();
    let ManifestDecisionV1::Advanced(head) = decision else { panic!("expected head advance"); };
    assert_eq!(manifest_outcome(first.advance(&head)), expected["exact_replay"]);

    let fork = SyncManifestV1::new_signed(&writer, [0x77; 16], 1, 1, [0; 32], vec![event_op(1, 2, SyncOperationKindV1::Correction, &[("app", json!("Other"))])]).unwrap();
    assert_eq!(manifest_outcome(fork.advance(&head)), expected["same_revision_different_hash"]);
    assert_eq!(manifest_outcome(first.advance(&SyncHeadV1::new(2, [7; 32]))), expected["lower_revision"]);
    let wrong_parent = SyncManifestV1::new_signed(&writer, [0x77; 16], 1, 2, [8; 32], vec![operation.clone()]).unwrap();
    assert_eq!(manifest_outcome(wrong_parent.advance(&head)), expected["wrong_parent"]);
    let gap = SyncManifestV1::new_signed(&writer, [0x77; 16], 1, 3, head.head_hash, vec![operation]).unwrap();
    assert_eq!(manifest_outcome(gap.advance(&head)), expected["revision_gap"]);
}

#[test]
fn signed_manifest_binds_and_canonicalizes_tombstone_acknowledgements() {
    let writer = signing_identity(7);
    let first = SyncTombstoneAckV1 {
        origin_device_id: URL_SAFE_NO_PAD.encode([0x71; 16]),
        local_event_id: 9,
        tombstone_counter: 4,
    };
    let second = SyncTombstoneAckV1 {
        origin_device_id: URL_SAFE_NO_PAD.encode([0x72; 16]),
        local_event_id: 10,
        tombstone_counter: 5,
    };
    let manifest = SyncManifestV1::new_signed_with_tombstone_acks(
        &writer,
        [0x73; 16],
        2,
        1,
        [0; 32],
        Vec::new(),
        vec![second.clone(), first.clone()],
    ).unwrap();
    assert_eq!(manifest.tombstone_acknowledgements, vec![first.clone(), second]);
    manifest.verify_signature(&writer.public_identity(), &[0x73; 16]).unwrap();

    let mut altered = manifest;
    altered.tombstone_acknowledgements[0].tombstone_counter += 1;
    assert!(altered.verify_signature(&writer.public_identity(), &[0x73; 16]).is_err());
}
