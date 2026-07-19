//! The cryptographic-key view of a profile — the dig-message / dig-chat / dig-node resolution seam.
//!
//! A DID resolves, via its profile's standard key slots, to the material a peer needs to talk to it:
//! the single BLS12-381 G1 identity key, a peer id, and the key epoch. Each is OPTIONAL — a profile
//! may omit any of them, and consumers must distinguish "absent" from "present", so these are
//! `Option`s, never zero-filled defaults.
//!
//! The v2 model publishes ONE identity key (slot `0x0010`): a 48-byte compressed BLS12-381 G1 public
//! key that serves BOTH the sender signature (BLS G2, AugSchemeMPL) and the seal DH (G1 ECDH). There
//! is no separate encryption key — the v1 X25519 slot `0x0011` is retired (SPEC §2.2, §6a).

/// The keys a profile publishes for its DID, as read from the standard key slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DidKeys {
    /// 48-byte compressed BLS12-381 G1 identity public key (slot `0x0010`), if published. Serves both
    /// signing (BLS G2) and sealing (G1 ECDH) — the single identity key of the v2 model (§6a).
    pub bls_g1_public_key: Option<[u8; 48]>,
    /// 32-byte peer id = `SHA-256(TLS SPKI DER)` (slot `0x0012`), if published.
    pub peer_id: Option<[u8; 32]>,
    /// Monotonic key epoch (slot `0x0013`), bumped on rotation, if published.
    pub key_epoch: Option<u32>,
}
