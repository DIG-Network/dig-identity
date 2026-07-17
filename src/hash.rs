//! sha256 primitives shared by slot-key derivation, leaf-value hashing, and the SMT node hasher.
//!
//! The whole format is anchored on **one** hash — sha256 — so a Rust, a JS, and a wasm reader all
//! reproduce byte-identical roots and proofs. Two concerns live here:
//!
//! 1. [`sha256`] — the flat digest used to derive slot keys ([`crate::slot`]) and to hash a slot's
//!    encoded value into the leaf it occupies.
//! 2. [`Sha256Hasher`] — the [`sparse_merkle_tree::traits::Hasher`] the Nervos tree calls to hash
//!    its internal branch nodes. We do NOT re-implement the merkle construction; we only supply the
//!    hash function it hashes nodes with, so node domain-separation (the tree's own `MERGE_NORMAL`
//!    `0x01` / `MERGE_ZEROS` `0x02` prefix bytes) is inherited from the audited crate.
//!
//! # Leaf-hash domain separation (why the slot key is bound in)
//!
//! A leaf digest is `sha256(0x01 ‖ slot_key ‖ encoded_value)`. The `0x01` prefix ALONE does NOT
//! guarantee non-confusion with a branch-node preimage: the Nervos `MERGE_NORMAL` branch preimage
//! also begins `0x01`, and because a [`crate::value::Value::Bytes`] payload is attacker-chosen, a
//! leaf preimage could be crafted byte-identical to a branch preimage. That collision is
//! non-exploitable in the merkle proof itself — the verifier folds every leaf from height 0 up to
//! 256, so its DEPTH ACCOUNTING (not the prefix byte) is what actually separates a leaf from a
//! branch. Binding the 32-byte `slot_key` into the leaf preimage makes the separation SELF-CONTAINED
//! and independent of the tree crate's internals: a leaf preimage now carries the fixed
//! `dig-identity` slot key, which no branch preimage does, so a second (JS/wasm) implementation is
//! robust even if it reasons about the domains directly.

use sha2::{Digest, Sha256};
use sparse_merkle_tree::{traits::Hasher, H256};

/// A 32-byte sha256 digest.
pub type Digest32 = [u8; 32];

/// Computes `sha256(data)`.
pub fn sha256(data: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The domain-prefix byte mixed into a slot's **leaf value** hash.
///
/// Leaf values are hashed as `sha256([LEAF_DOMAIN] ‖ slot_key ‖ encoded_value)`; see the module
/// docs for why the slot key is bound in rather than relying on the prefix byte alone. `0x01`
/// mirrors the ecosystem's chia-style leaf-domain convention.
pub const LEAF_DOMAIN: u8 = 0x01;

/// Hashes a slot's already-encoded value into the 32-byte leaf it occupies in the tree.
///
/// The digest is `sha256(0x01 ‖ slot_key ‖ encoded_value)` — binding the 32-byte `slot_key` makes
/// the leaf domain self-contained (module docs). An empty `encoded_value` denotes an **absent** slot
/// and hashes to the all-zero digest regardless of `slot_key`, which the sparse merkle tree treats
/// as "no leaf here" — this is what makes non-membership provable.
pub fn hash_leaf_value(slot_key: &Digest32, encoded_value: &[u8]) -> Digest32 {
    if encoded_value.is_empty() {
        return [0u8; 32];
    }
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    hasher.update(slot_key);
    hasher.update(encoded_value);
    hasher.finalize().into()
}

/// The sha256 hasher the Nervos sparse merkle tree uses for its internal branch nodes.
///
/// It accumulates the bytes the tree feeds it (branch-merge prefix, height, node key, child
/// digests) and finalizes to sha256 — making the whole tree sha256-based end to end.
#[derive(Default)]
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Hasher for Sha256Hasher {
    fn write_h256(&mut self, h: &H256) {
        self.inner.update(h.as_slice());
    }

    fn write_byte(&mut self, b: u8) {
        self.inner.update([b]);
    }

    fn finish(self) -> H256 {
        let out: Digest32 = self.inner.finalize().into();
        out.into()
    }
}
