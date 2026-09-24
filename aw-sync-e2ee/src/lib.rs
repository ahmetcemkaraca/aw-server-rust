mod crypto;
mod merge;
mod pairing;
mod recovery;
mod snapshot;
mod store;

pub use aw_models::{
    DevicePublicIdentityV1, EncryptedKeyTransferV1, PairingConfirmationV1,
    PairingInvitationV1, PairingOfferV1, PairingResponseV1, RecoveryKitV1,
    SyncRelayOperationV1, SyncRelayRequestV1, SyncRelayResponseV1,
};

pub use crypto::{
    create_vault_data_key, decrypt_chunk, encrypt_chunk, generate_account_root_key,
    reencrypt_snapshot_chunks, rotate_account_and_vault_key, unwrap_vault_data_key,
    AccountRootKeyV1, SyncErrorV1, SyncKeyMaterialBundleV1, VaultDataKeyV1,
    WrappedVaultDataKeyV1,
};
pub use merge::{
    create_event_correction, create_event_tombstone, create_event_upsert, create_policy_change,
    decode_sync_data_field_v1, decrypt_manifest, encode_sync_data_field_v1, encrypt_manifest,
    merge_operations, pending_tombstone_ack_device_ids,
    tombstone_collectible,
    ManifestDecisionV1, MergeConflictV1, MergeErrorV1, MergeResultV1, MergedEventV1,
    PendingPolicyConflictV1, SyncHeadV1, SyncManifestV1, SyncOperationV1,
    SyncTombstoneAckV1,
    SyncTombstoneAckProofV1, SyncTombstoneDeletionPermitV1,
};
pub use pairing::{
    accept_key_transfer, begin_pairing, complete_pairing, confirm_pairing,
    create_key_transfer, derive_pairing_session, generate_device_identity,
    respond_to_pairing, DeviceIdentityV1, PairingEphemeralKeyV1, PairingSessionV1,
};
pub use recovery::create_recovery_kit;
pub use recovery::open_recovery_kit;
pub use snapshot::{decrypt_snapshot, encrypt_snapshot, inspect_snapshot_chunk, EncryptedSyncSnapshotV1, SnapshotChunkMetadataV1};
pub use store::{
    FolderSyncObjectStoreV1, SyncHttpObjectStoreV1, SyncObjectStoreErrorV1,
    SyncObjectStoreV1, SyncRelayTransportV1,
};

#[cfg(test)]
mod crypto_tests;

#[cfg(test)]
mod pairing_tests;

#[cfg(test)]
mod merge_tests;

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod key_rotation_tests;

#[cfg(test)]
mod snapshot_tests;

#[cfg(test)]
mod store_tests;
