//! # dig-identity — the canonical DIG decentralized-identity profile format
//!
//! A DIG identity is an **identity anchor** (a Chia `did:chia:` singleton in v1) PAIRED with a
//! chip35 DataLayer store that holds the anchor's **profile**. The profile is a **sparse merkle
//! tree** of standard SLOTS — one fixed 256-bit position per field — so any implementation reads
//! and writes the same bytes, and any field can be proved (or proved absent) against a single
//! 32-byte root.
//!
//! This crate is **WU1**: the pure, CHAIN-INDEPENDENT format layer. It has NO chain calls, NO
//! chip35 dependency, and NO DID resolution — those are WU2/WU3. It is also **keyless**: it never
//! signs (dig-node's signer does that later, mirroring chip35's posture).
//!
//! ## What lives here
//!
//! | Concern | Module |
//! |---|---|
//! | Slot ids, the v1 slot map, slot-key derivation | [`slot`] |
//! | The `tag ‖ len ‖ bytes` value encoding | [`value`] |
//! | sha256 primitives + the SMT node hasher | [`hash`] |
//! | The mutable tree: set/get/root/prove | [`tree`] |
//! | Serializable proofs + root-only verification | [`proof`] |
//! | The profile reader/writer + key resolution | [`profile`] / [`keys`] |
//! | The identity anchor (DID) + discovery parse | [`did`] |
//! | The DID↔store bidirectional-pairing predicate | [`pairing`] |
//!
//! ## Proving a field against a root
//!
//! ```
//! use dig_identity::{Profile, Value, slot::standard, proof};
//!
//! let mut profile = Profile::with_schema_v1();
//! profile.set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()));
//!
//! let tree = profile.build_tree().unwrap();
//! let root = tree.root();
//!
//! // Prove the display name equals "Ada" using only (root, proof).
//! let membership = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
//! let claim = Value::Utf8("Ada".into());
//! assert!(proof::verify_membership(&root, standard::DISPLAY_NAME, &claim, &membership).unwrap());
//!
//! // Prove no encryption key is present.
//! let absent = tree.prove_non_membership(standard::ENCRYPTION_PUBLIC_KEY).unwrap();
//! assert!(proof::verify_non_membership(&root, standard::ENCRYPTION_PUBLIC_KEY, &absent).unwrap());
//! ```

pub mod did;
pub mod error;
pub mod hash;
pub mod keys;
pub mod pairing;
pub mod profile;
pub mod proof;
pub mod slot;
pub mod tree;
pub mod value;

pub use did::{parse_did_from_description, Did};
pub use error::{Error, Result};
pub use keys::DidKeys;
pub use pairing::{
    evaluate_pairing, is_authoritative_profile, IdentitySingleton, PairingOutcome, StoreRecord,
};

// Re-export the canonical Chia types the public API speaks, so consumers pin the same versions.
pub use chia_protocol::{Bytes32, Coin};
pub use profile::{resolve_did_keys, Profile};
pub use proof::{verify_membership, verify_non_membership, ProfileProof};
pub use slot::SlotId;
pub use tree::ProfileTree;
pub use value::{Value, ValueTag};
