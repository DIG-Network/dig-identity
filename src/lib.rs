//! # dig-identity — the canonical DIG decentralized-identity profile format
//!
//! A DIG identity is an **identity anchor** (a Chia `did:chia:` singleton in v1) PAIRED with a
//! chip35 DataLayer store that holds the anchor's **profile**. The profile is a **sparse merkle
//! tree** of standard SLOTS — one fixed 256-bit position per field — so any implementation reads
//! and writes the same bytes, and any field can be proved (or proved absent) against a single
//! 32-byte root.
//!
//! The format core is **CHAIN-INDEPENDENT** (no chain calls, no chip35 dependency). WU3 adds on-chain
//! DID resolution as a caller-supplied [`ChainSource`] TRAIT seam ([`resolve`]), so the crate still
//! holds no network dependency and builds unchanged for wasm / no-network targets. The v2 **BLS
//! identity key model** ([`bls`], SPEC §6a) — the single BLS12-381 G1 key that does both sign (G2)
//! and seal-DH (G1) — is behind the default-on `bls` feature, so the pure format layer still builds
//! with `default-features = false`. The DID→dig-store minting driver (WU2) remains a follow-on.
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
//! | The canonical XCH receive-address field codec | [`xch`] |
//! | The DID↔store bidirectional-pairing predicate + ownership proof | [`pairing`] |
//! | Composed "this datum belongs to this DID" verification | [`verify`] |
//! | On-chain DID→profile resolution over a caller [`ChainSource`] (WU3) | [`resolve`] |
//! | The BLS12-381 G1 identity key model: derivation + sign/seal primitives (§6a) | [`bls`] |
//!
//! ## Proving a field against a root
//!
//! ```
//! use dig_identity::{Profile, Value, slot::standard, proof};
//!
//! let mut profile = Profile::with_schema_v2();
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
//! // Prove no peer id is present.
//! let absent = tree.prove_non_membership(standard::PEER_ID).unwrap();
//! assert!(proof::verify_non_membership(&root, standard::PEER_ID, &absent).unwrap());
//! ```

#[cfg(feature = "bls")]
pub mod bls;
pub mod did;
pub mod error;
pub mod hash;
pub mod identity_profile;
pub mod keys;
pub mod pairing;
pub mod profile;
pub mod proof;
pub mod resolve;
pub mod slot;
pub mod tree;
pub mod value;
pub mod verify;
pub mod xch;

pub use did::{parse_did_from_description, Did};
pub use error::{Error, Result};
pub use identity_profile::IdentityProfile;
pub use keys::DidKeys;
pub use pairing::{
    evaluate_pairing, is_authoritative_profile, store_belongs_to_did, IdentitySingleton,
    PairingOutcome, SingletonLineage, StoreOwnershipProof, StoreRecord,
};

// Re-export the canonical Chia types the public API speaks, so consumers pin the same versions.
pub use chia_protocol::{Bytes32, Coin};
pub use profile::{resolve_did_keys, Profile};
pub use proof::{verify_membership, verify_non_membership, ProfileProof};
// The WU3 on-chain resolution seam. The chain `resolve_did_keys` stays module-qualified
// (`resolve::resolve_did_keys`) to avoid colliding with the networkless [`profile::resolve_did_keys`].
pub use resolve::{
    resolve_bls_public_key, resolve_identity_profile, ChainSource, ChainStoreState, ResolveError,
};
// The BLS12-381 G1 identity key model (§6a), behind the default-on `bls` feature.
#[cfg(feature = "bls")]
pub use bls::{
    derive_identity_sk, derive_identity_sk_at, g1_dh, g1_subgroup_check,
    master_secret_key_from_seed, public_key_bytes, sign_message, verify_signature,
    IDENTITY_DERIVATION_PATH,
};
pub use slot::SlotId;
pub use tree::ProfileTree;
pub use value::{Value, ValueTag};
pub use verify::{verify_profile_field_absent_for_did, verify_profile_field_for_did};
pub use xch::{is_valid_xch_address, parse_xch_address};
