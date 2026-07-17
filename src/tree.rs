//! The mutable profile tree: set/get slots, compute the root, and produce proofs.
//!
//! [`ProfileTree`] is a thin, intent-revealing wrapper over the Nervos sparse merkle tree. It maps
//! [`SlotId`]s to their derived 256-bit keys, hashes each slot's encoded value into its leaf, and
//! exposes exactly the operations a profile writer/reader needs. The merkle mechanics themselves —
//! branch hashing, proof compilation, non-membership handling — are the audited crate's, not ours.

use sparse_merkle_tree::{
    default_store::DefaultStore, traits::Value as SmtValue, SparseMerkleTree, H256,
};

use crate::error::{Error, Result};
use crate::hash::{hash_leaf_value, Sha256Hasher};
use crate::proof::ProfileProof;
use crate::slot::SlotId;
use crate::value::Value;

/// The leaf a slot occupies: its already-encoded value bytes.
///
/// The SMT hashes this into a 32-byte digest via [`SmtValue::to_h256`], applying the leaf domain
/// prefix. An empty blob is the canonical "absent slot" and hashes to zero, which the tree treats
/// as no-leaf — the basis for non-membership proofs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LeafValue(Vec<u8>);

impl SmtValue for LeafValue {
    fn to_h256(&self) -> H256 {
        H256::from(hash_leaf_value(&self.0))
    }

    fn zero() -> Self {
        LeafValue(Vec::new())
    }
}

type Smt = SparseMerkleTree<Sha256Hasher, LeafValue, DefaultStore<LeafValue>>;

/// A mutable DIG profile as a sparse merkle tree of slots.
#[derive(Default)]
pub struct ProfileTree {
    smt: Smt,
}

impl ProfileTree {
    /// Creates an empty profile tree (root = all zeros).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `slot` to `value`, replacing any prior value at that slot.
    pub fn set(&mut self, slot: SlotId, value: &Value) -> Result<()> {
        self.set_encoded(slot, value.encode())
    }

    /// Sets `slot` to a pre-encoded value blob (used when relaying bytes without re-decoding them).
    pub fn set_encoded(&mut self, slot: SlotId, encoded: Vec<u8>) -> Result<()> {
        self.smt
            .update(H256::from(slot.key()), LeafValue(encoded))
            .map(|_| ())
            .map_err(|e| Error::Smt(e.to_string()))
    }

    /// Removes `slot`, making it provably absent.
    pub fn remove(&mut self, slot: SlotId) -> Result<()> {
        self.set_encoded(slot, Vec::new())
    }

    /// Returns the pre-encoded value bytes at `slot`, or `None` if the slot is absent.
    pub fn get_encoded(&self, slot: SlotId) -> Result<Option<Vec<u8>>> {
        let leaf = self
            .smt
            .get(&H256::from(slot.key()))
            .map_err(|e| Error::Smt(e.to_string()))?;
        Ok(if leaf.0.is_empty() {
            None
        } else {
            Some(leaf.0)
        })
    }

    /// Returns the decoded value at `slot`, or `None` if the slot is absent.
    pub fn get(&self, slot: SlotId) -> Result<Option<Value>> {
        match self.get_encoded(slot)? {
            Some(bytes) => Value::decode(&bytes).map(Some),
            None => Ok(None),
        }
    }

    /// The current 32-byte merkle root committing to every set slot.
    ///
    /// This is the value dig-identity DEFINES; WU3 pairs it with the on-chain DataStore root.
    pub fn root(&self) -> [u8; 32] {
        (*self.smt.root()).into()
    }

    /// Builds a membership proof that `slot` currently holds its set value.
    ///
    /// Errors if `slot` is absent — use [`ProfileTree::prove_non_membership`] for that case so the
    /// intent (present vs absent) is explicit at the call site.
    pub fn prove_membership(&self, slot: SlotId) -> Result<ProfileProof> {
        if self.get_encoded(slot)?.is_none() {
            return Err(Error::Smt(format!(
                "slot 0x{:04x} is absent; use prove_non_membership",
                slot.0
            )));
        }
        self.prove(slot)
    }

    /// Builds a non-membership proof that `slot` is currently absent.
    ///
    /// Errors if `slot` is present, to prevent minting a "non-membership" proof for a set slot.
    pub fn prove_non_membership(&self, slot: SlotId) -> Result<ProfileProof> {
        if self.get_encoded(slot)?.is_some() {
            return Err(Error::Smt(format!(
                "slot 0x{:04x} is present; use prove_membership",
                slot.0
            )));
        }
        self.prove(slot)
    }

    /// Compiles a proof for `slot`'s key regardless of presence (shared by both prove_* entry points).
    fn prove(&self, slot: SlotId) -> Result<ProfileProof> {
        let key = H256::from(slot.key());
        let proof = self
            .smt
            .merkle_proof(vec![key])
            .map_err(|e| Error::Smt(e.to_string()))?;
        let compiled = proof
            .compile(vec![key])
            .map_err(|e| Error::Smt(e.to_string()))?;
        Ok(ProfileProof(compiled.0))
    }
}
