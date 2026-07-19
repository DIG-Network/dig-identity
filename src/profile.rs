//! The [`Profile`] reader/writer — a slot map that materializes into a [`ProfileTree`].
//!
//! A reader who knows a profile's slot values (from a store read) assembles them into a `Profile`,
//! then materializes the tree to recompute the root or mint proofs. A writer builds a `Profile`
//! field by field. Convenience accessors decode the standard slots into their natural Rust types;
//! [`Profile::resolve_keys`] extracts the cryptographic-key view (the dig-chat/dig-node seam).

use std::collections::BTreeMap;

use crate::error::Result;
use crate::keys::DidKeys;
use crate::slot::{standard, SlotId};
use crate::tree::ProfileTree;
use crate::value::Value;

/// A DIG profile as an ordered map of slot id to value.
///
/// Ordering is deterministic (`BTreeMap`) so iteration and any derived artifact are reproducible.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    slots: BTreeMap<SlotId, Value>,
}

impl Profile {
    /// Creates an empty profile.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a profile pre-stamped with the v2 schema version in slot `0x0000`.
    pub fn with_schema_v2() -> Self {
        let mut profile = Self::new();
        profile.set(
            standard::SCHEMA_VERSION,
            Value::U16(standard::SCHEMA_VERSION_V2),
        );
        profile
    }

    /// Sets a slot to a value, replacing any prior value at that slot.
    pub fn set(&mut self, slot: SlotId, value: Value) -> &mut Self {
        self.slots.insert(slot, value);
        self
    }

    /// Returns the raw value at a slot, or `None` if unset.
    pub fn get(&self, slot: SlotId) -> Option<&Value> {
        self.slots.get(&slot)
    }

    /// Iterates every set `(slot, value)` in deterministic slot order.
    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &Value)> {
        self.slots.iter()
    }

    /// The schema version written in slot `0x0000`, if present.
    pub fn schema_version(&self) -> Option<u16> {
        match self.get(standard::SCHEMA_VERSION) {
            Some(Value::U16(v)) => Some(*v),
            _ => None,
        }
    }

    /// The display name (slot `0x0001`), if present and UTF-8.
    pub fn display_name(&self) -> Option<&str> {
        self.utf8(standard::DISPLAY_NAME)
    }

    /// The bio (slot `0x0002`), if present and UTF-8.
    pub fn bio(&self) -> Option<&str> {
        self.utf8(standard::BIO)
    }

    /// The XCH receive address (slot `0x0008`), if present and a canonical mainnet `xch1…` address.
    ///
    /// Returns `None` when the slot is unset, is not UTF-8, or does not decode as a canonical XCH
    /// address (wrong HRP / bad Bech32m checksum / non-32-byte payload) — so a caller can safely use
    /// the returned string as a payment destination (the $DIG-payments seam, [`crate::xch`]).
    pub fn xch_address(&self) -> Option<&str> {
        let raw = self.utf8(standard::XCH_ADDRESS)?;
        crate::xch::is_valid_xch_address(raw).then_some(raw)
    }

    /// Extracts the cryptographic-key view from the standard key slots (the DID→keys resolution).
    pub fn resolve_keys(&self) -> DidKeys {
        DidKeys {
            bls_g1_public_key: self.bytes48(standard::BLS_G1_PUBLIC_KEY),
            peer_id: self.bytes32(standard::PEER_ID),
            key_epoch: match self.get(standard::KEY_EPOCH) {
                Some(Value::U32(v)) => Some(*v),
                _ => None,
            },
        }
    }

    /// Materializes the profile into its sparse merkle tree (for the root and proofs).
    pub fn build_tree(&self) -> Result<ProfileTree> {
        let mut tree = ProfileTree::new();
        for (slot, value) in &self.slots {
            tree.set(*slot, value)?;
        }
        Ok(tree)
    }

    /// Computes the profile's merkle root without retaining the tree.
    pub fn build_root(&self) -> Result<[u8; 32]> {
        Ok(self.build_tree()?.root())
    }

    /// Reads a UTF-8 slot as `&str`, or `None` when unset or a non-UTF-8 type.
    fn utf8(&self, slot: SlotId) -> Option<&str> {
        match self.get(slot) {
            Some(Value::Utf8(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Reads a `Bytes` slot as a 32-byte array, or `None` when unset or not exactly 32 bytes.
    fn bytes32(&self, slot: SlotId) -> Option<[u8; 32]> {
        match self.get(slot) {
            Some(Value::Bytes(b)) if b.len() == 32 => Some(b.as_slice().try_into().ok()?),
            _ => None,
        }
    }

    /// Reads a `Bytes` slot as a 48-byte array, or `None` when unset or not exactly 48 bytes.
    ///
    /// The 48-byte width is the compressed BLS12-381 G1 identity key (slot `0x0010`, §6a). A slot
    /// carrying the wrong length is treated as absent — a consumer never receives a malformed key.
    fn bytes48(&self, slot: SlotId) -> Option<[u8; 48]> {
        match self.get(slot) {
            Some(Value::Bytes(b)) if b.len() == 48 => Some(b.as_slice().try_into().ok()?),
            _ => None,
        }
    }
}

/// Extracts the DID's published keys from its profile (the dig-chat / dig-node resolution helper).
///
/// A thin free-function alias for [`Profile::resolve_keys`], named for the call site that reads
/// "resolve this DID's keys".
pub fn resolve_did_keys(profile: &Profile) -> DidKeys {
    profile.resolve_keys()
}
