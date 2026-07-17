//! The serializable proof blob and the root-only verification functions.
//!
//! A [`ProfileProof`] is the compact compiled form of a sparse-merkle-tree proof for a single slot.
//! The verify functions are **standalone**: given only a root hash, a slot, the claimed value (or
//! its absence), and the proof, they decide whether that claim holds — no access to the tree. This
//! is the property dig-chat and dig-node rely on to check "this DID's field == X" against an
//! on-chain root without pulling the whole profile.

use sparse_merkle_tree::{CompiledMerkleProof, H256};

use crate::error::Result;
use crate::hash::{hash_leaf_value, Sha256Hasher};
use crate::slot::SlotId;
use crate::value::Value;

/// A compiled sparse-merkle-tree proof for one slot, ready to serialize, store, or transmit.
///
/// Membership and non-membership proofs share this type — the distinction lives in which verify
/// function is applied, since a non-membership proof simply proves the slot's leaf is the zero leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileProof(pub Vec<u8>);

impl ProfileProof {
    /// Borrows the raw compiled-proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wraps raw compiled-proof bytes received from storage or the wire.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        ProfileProof(bytes)
    }
}

/// Verifies that `slot` holds exactly `value` in the tree committed to by `root`.
///
/// Returns `Ok(true)` only when the proof reconstructs `root` from the leaf
/// `(slot_key, hash_leaf_value(encode(value)))`. A tampered value, a wrong slot, or a proof lifted
/// from a different slot all reconstruct a different root and yield `Ok(false)`.
pub fn verify_membership(
    root: &[u8; 32],
    slot: SlotId,
    value: &Value,
    proof: &ProfileProof,
) -> Result<bool> {
    let leaf_hash = hash_leaf_value(&value.encode());
    verify_leaf(root, slot, leaf_hash, proof)
}

/// Verifies that `slot` is ABSENT from the tree committed to by `root`.
///
/// Non-membership is proved as membership of the all-zero leaf at the slot's key, which the sparse
/// merkle tree represents natively — so "no encryption key is present" is a first-class, provable
/// statement (dig-chat distinguishes absent from present).
pub fn verify_non_membership(root: &[u8; 32], slot: SlotId, proof: &ProfileProof) -> Result<bool> {
    verify_leaf(root, slot, [0u8; 32], proof)
}

/// Shared verification core: reconstruct the root from `(slot_key, leaf_hash)` and compare.
fn verify_leaf(
    root: &[u8; 32],
    slot: SlotId,
    leaf_hash: [u8; 32],
    proof: &ProfileProof,
) -> Result<bool> {
    let compiled = CompiledMerkleProof(proof.0.clone());
    let leaves = vec![(H256::from(slot.key()), H256::from(leaf_hash))];
    compiled
        .verify::<Sha256Hasher>(&H256::from(*root), leaves)
        .map_err(|e| crate::error::Error::Smt(e.to_string()))
}
