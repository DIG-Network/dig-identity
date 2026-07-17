//! Slot identifiers, the v1 standard slot map, and the deterministic slot-key derivation.
//!
//! A profile is a sparse merkle tree keyed by **slot key**, not by the raw slot id. The slot key is
//! `sha256("dig-identity:slot:" ‖ u32_be(slot_id))` — a fixed derivation so every implementation
//! places a given field at the same 256-bit position, and so slot ids stay small + human-readable
//! while their tree positions are spread uniformly across the key space.
//!
//! # Additive-only (HARD RULE)
//!
//! The slot map is a permanent on-chain-anchored contract (CLAUDE.md §5.1 spirit). New capability is
//! added ONLY by allocating a new slot id. An existing slot id is NEVER renumbered, repurposed, or
//! re-encoded, and a reader MUST ignore slot ids it does not recognize rather than reject the
//! profile — so an old reader keeps working against a newer writer's tree.

use crate::hash::{sha256, Digest32};

/// A profile slot identifier (`0x0000`..=`0xFFFF`).
///
/// The id is the small, stable, human-readable name of a field; its position in the tree is the
/// derived [`SlotId::key`]. Ids are grouped into the reserved ranges documented on the range
/// predicates below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(pub u16);

/// The domain string prefixing every slot-key preimage, keeping slot keys in their own hash domain.
const SLOT_KEY_DOMAIN: &[u8] = b"dig-identity:slot:";

impl SlotId {
    /// Derives this slot's 256-bit tree key: `sha256("dig-identity:slot:" ‖ u32_be(slot_id))`.
    ///
    /// The id is widened to a big-endian `u32` in the preimage (fixed forever) even though ids fit
    /// in a `u16`, so the derivation is unambiguous across languages.
    pub fn key(self) -> Digest32 {
        let mut preimage = Vec::with_capacity(SLOT_KEY_DOMAIN.len() + 4);
        preimage.extend_from_slice(SLOT_KEY_DOMAIN);
        preimage.extend_from_slice(&(self.0 as u32).to_be_bytes());
        sha256(&preimage)
    }

    /// `true` for `0x0000`..=`0x00FF` — reserved for future STANDARD slots defined by this crate.
    pub fn is_future_standard(self) -> bool {
        self.0 <= 0x00FF
    }

    /// `true` for `0x0100`..=`0x0FFF` — reserved for ecosystem-extension slots.
    pub fn is_ecosystem_extension(self) -> bool {
        (0x0100..=0x0FFF).contains(&self.0)
    }

    /// `true` for `0x1000`..=`0xEFFF` — free for application-defined custom slots.
    pub fn is_custom(self) -> bool {
        (0x1000..=0xEFFF).contains(&self.0)
    }

    /// `true` for `0xF000`..=`0xFFFF` — reserved for encrypted slots (the v2 privacy layer).
    pub fn is_encrypted_reserved(self) -> bool {
        self.0 >= 0xF000
    }
}

/// The v1 standard slot ids. Fixed forever; new fields are appended, never re-numbered (§5.1).
pub mod standard {
    use super::SlotId;

    /// `u16` = 1. The profile schema version the tree was written against.
    pub const SCHEMA_VERSION: SlotId = SlotId(0x0000);
    /// UTF-8 display name.
    pub const DISPLAY_NAME: SlotId = SlotId(0x0001);
    /// UTF-8 free-text bio.
    pub const BIO: SlotId = SlotId(0x0002);
    /// UTF-8 `dig://` URN of the avatar image.
    pub const AVATAR: SlotId = SlotId(0x0003);
    /// UTF-8 `dig://` URN of the banner image.
    pub const BANNER: SlotId = SlotId(0x0004);
    /// UTF-8 pronouns.
    pub const PRONOUNS: SlotId = SlotId(0x0005);
    /// UTF-8 location.
    pub const LOCATION: SlotId = SlotId(0x0006);
    /// UTF-8 newline-separated social/verification links.
    pub const LINKS: SlotId = SlotId(0x0007);

    /// 32-byte Ed25519 signing public key. Feeds DID→keys resolution (dig-chat, dig-node).
    pub const SIGNING_PUBLIC_KEY: SlotId = SlotId(0x0010);
    /// 32-byte X25519 identity public key (encryption). Feeds DID→keys resolution.
    pub const ENCRYPTION_PUBLIC_KEY: SlotId = SlotId(0x0011);
    /// 32-byte peer id = `SHA-256(TLS SPKI DER)`. Feeds DID→keys resolution.
    pub const PEER_ID: SlotId = SlotId(0x0012);
    /// `u32` key epoch — bumped on each key rotation.
    pub const KEY_EPOCH: SlotId = SlotId(0x0013);

    /// `u64` Unix-seconds last-updated timestamp.
    pub const UPDATED_AT: SlotId = SlotId(0x0018);

    /// The schema version this crate writes.
    pub const SCHEMA_VERSION_V1: u16 = 1;
}
