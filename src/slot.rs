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
//!
//! ## Schema v2 reset (one-time pre-release exception)
//!
//! This revision re-encoded slot `0x0010` (v1 Ed25519 → v2 48-byte BLS12-381 G1) and retired slot
//! `0x0011` (v1 X25519). This is the ONE sanctioned break of the additive-only rule, permitted ONLY
//! because the crate is pre-1.0 and pre-release with ZERO on-chain profiles to protect (SPEC §2.4):
//! there are no shipped bytes to keep readable. [`standard::SCHEMA_VERSION_V2`] records the reset.
//! From this revision onward the additive-only rule is absolute again.

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

/// The v2 standard slot ids. Additive-only from this revision; new fields are appended, never
/// re-numbered (§2.4). The v2 reset re-encoded `0x0010` and retired `0x0011` (see the module doc).
pub mod standard {
    use super::SlotId;

    /// `u16` = 2. The profile schema version the tree was written against.
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
    /// UTF-8 canonical mainnet XCH receive address (`xch1…`, bech32m). The $DIG-payments seam:
    /// tip or pay the identity. Validated as a canonical `xch` address on read
    /// ([`crate::xch::parse_xch_address`]).
    pub const XCH_ADDRESS: SlotId = SlotId(0x0008);

    /// 48-byte compressed BLS12-381 **G1** identity public key — the SINGLE identity key (§6a). It
    /// serves BOTH the sender signature (BLS G2, AugSchemeMPL) and the seal DH (G1 ECDH). Feeds
    /// DID→keys resolution (dig-message, dig-chat, dig-node).
    ///
    /// v2 re-encoding: this slot held a 32-byte Ed25519 key in v1; the v2 schema reset repurposed it
    /// to the 48-byte BLS G1 key (the ONLY sanctioned break of the additive-only rule — pre-release,
    /// zero on-chain profiles). See the module doc.
    pub const BLS_G1_PUBLIC_KEY: SlotId = SlotId(0x0010);

    // Slot `0x0011` (v1 X25519 encryption key) is RETIRED in v2 — the one BLS G1 key at `0x0010`
    // does both sign and seal, so there is no separate encryption key. The id is not reused.

    /// 32-byte peer id = `SHA-256(TLS SPKI DER)`. Feeds DID→keys resolution.
    pub const PEER_ID: SlotId = SlotId(0x0012);
    /// `u32` key epoch — bumped on each key rotation.
    pub const KEY_EPOCH: SlotId = SlotId(0x0013);

    /// `u64` Unix-seconds last-updated timestamp.
    pub const UPDATED_AT: SlotId = SlotId(0x0018);

    /// The schema version this crate writes (v2 — the BLS-G1-only key model).
    pub const SCHEMA_VERSION_V2: u16 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Pins the slot-key derivation to its FROZEN output for two standard slots.
    ///
    /// These digests were captured from dig-identity v0.4.2 and are a permanent, on-chain-anchored
    /// contract (§5.1): a drift moves the field's position in every published profile's tree and
    /// silently invalidates every proof ever written against it.
    ///
    /// `tests/format.rs::slot_key_matches_documented_preimage` is a genuinely independent check of the
    /// DOMAIN: it hardcodes the `"dig-identity:slot:"` literal rather than referencing
    /// `SLOT_KEY_DOMAIN`, so a change to that constant DOES fail it. What it cannot see is a change
    /// INSIDE the shared machinery it reuses — `hash::sha256` and the `u32` big-endian widening are
    /// the same code production runs, so swapping either would move both sides together and the test
    /// would stay green. This frozen vector is external to the entire derivation and fails if ANY
    /// input to it moves — domain, widening, or hash.
    #[test]
    fn slot_key_derivation_is_frozen() {
        assert_eq!(
            to_hex(&standard::SCHEMA_VERSION.key()),
            "b57afbeb86bb7c09c73cbb809ca1f24198610f8d4a642c08c3bbd101bc72dd9e"
        );
        assert_eq!(
            to_hex(&standard::DISPLAY_NAME.key()),
            "d504c074b73a0c7e62ff69fc7f5ce0e278d0350ea9277385480587a4d29836d7"
        );
    }

    /// How many of the four range predicates claim `id`. A partition means EXACTLY one, always.
    fn matching_range_count(id: SlotId) -> usize {
        [
            id.is_future_standard(),
            id.is_ecosystem_extension(),
            id.is_custom(),
            id.is_encrypted_reserved(),
        ]
        .into_iter()
        .filter(|matched| *matched)
        .count()
    }

    /// The four reserved ranges PARTITION `0x0000..=0xFFFF`: no gap and no overlap.
    ///
    /// `tests/format.rs::reserved_ranges_classify_correctly` pins each range's FIRST id only, so it
    /// cannot see a boundary that has drifted upward. Asserting the expected predicate at both ENDS
    /// is still not enough either: a widened lower bound (say `is_custom` becoming `self.0 >= 0x1000`)
    /// leaves every such assertion true while `0xF000` falls in TWO ranges. So this counts how many
    /// predicates claim each probe and requires the count to be EXACTLY ONE — which is the partition
    /// property itself, not merely the tiling half of it.
    #[test]
    fn slot_id_ranges_partition_the_id_space() {
        assert!(SlotId(0x0000).is_future_standard());
        assert!(SlotId(0x00FF).is_future_standard());
        assert!(SlotId(0x0100).is_ecosystem_extension());
        assert!(SlotId(0x0FFF).is_ecosystem_extension());
        assert!(SlotId(0x1000).is_custom());
        assert!(SlotId(0xEFFF).is_custom());
        assert!(SlotId(0xF000).is_encrypted_reserved());
        assert!(SlotId(0xFFFF).is_encrypted_reserved());

        for raw in [
            0x0000, 0x0080, 0x00FF, 0x0100, 0x0800, 0x0FFF, 0x1000, 0x8000, 0xEFFF, 0xF000, 0xF800,
            0xFFFF,
        ] {
            let id = SlotId(raw);
            assert_eq!(
                matching_range_count(id),
                1,
                "slot id {raw:#06x} must belong to exactly one reserved range"
            );
        }
    }
}
