//! The cryptographic-key view of a profile — the dig-chat / dig-node resolution seam.
//!
//! A DID resolves, via its profile's standard key slots, to the material a peer needs to talk to
//! it: an Ed25519 signing key, an X25519 encryption key, a peer id, and the key epoch. Each is
//! OPTIONAL — a profile may omit any of them, and consumers (dig-chat especially) must distinguish
//! "absent" from "present", so these are `Option`s, never zero-filled defaults.

/// The keys a profile publishes for its DID, as read from the standard key slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DidKeys {
    /// 32-byte Ed25519 signing public key (slot `0x0010`), if published.
    pub signing_public_key: Option<[u8; 32]>,
    /// 32-byte X25519 identity/encryption public key (slot `0x0011`), if published.
    pub encryption_public_key: Option<[u8; 32]>,
    /// 32-byte peer id = `SHA-256(TLS SPKI DER)` (slot `0x0012`), if published.
    pub peer_id: Option<[u8; 32]>,
    /// Monotonic key epoch (slot `0x0013`), bumped on rotation, if published.
    pub key_epoch: Option<u32>,
}
