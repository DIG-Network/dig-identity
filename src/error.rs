//! The crate's single error type.
//!
//! Every fallible public function returns [`Error`]; variants name the exact failure so a caller
//! (or an agent reading a log) can branch on the cause without parsing a string.

use thiserror::Error;

/// A failure decoding a value, building/proving over the tree, or evaluating the pairing predicate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// A value blob was shorter than its declared header or length prefix.
    #[error("value encoding is truncated: {0}")]
    TruncatedValue(&'static str),

    /// A value's declared length did not match the bytes that followed it.
    #[error("value length prefix ({declared}) does not match the {actual} bytes present")]
    LengthMismatch {
        /// The length written in the 4-byte big-endian prefix.
        declared: usize,
        /// The number of payload bytes actually present.
        actual: usize,
    },

    /// A value blob carried a tag byte this version does not define.
    #[error("unknown value tag 0x{0:02x}")]
    UnknownTag(u8),

    /// A fixed-width value (u16/u32/u64) carried the wrong number of payload bytes.
    #[error("fixed-width value for tag 0x{tag:02x} expected {expected} bytes, got {actual}")]
    WrongWidth {
        /// The value tag whose width was violated.
        tag: u8,
        /// The exact payload width the tag mandates.
        expected: usize,
        /// The payload width actually present.
        actual: usize,
    },

    /// The underlying sparse-merkle-tree rejected an update or proof operation.
    #[error("sparse-merkle-tree error: {0}")]
    Smt(String),

    /// A composed profile-field verification was declined because the supplied store is NOT the
    /// DID's authoritative profile (the DID↔store pairing predicate failed — see [`crate::pairing`]).
    #[error("store is not the DID's authoritative profile (pairing predicate failed)")]
    NotAuthoritativeProfile,

    /// A composed profile-field verification was declined because the merkle proof did not verify
    /// the claimed value (or absence) against the supplied profile root.
    #[error("profile-field merkle proof did not verify against the profile root")]
    FieldProofRejected,

    /// `IdentityProfile::mint_from_did` is not yet implemented. Minting is GATED on the dig-store
    /// crate (#703/#754) and the WU3 chain layer (#778); dig-identity MUST NOT depend on dig-store
    /// (the dependency graph stays acyclic), so the launch driver lands as a WU2 follow-on — not
    /// here. The signature exists now so consumers code against the primitive's final shape.
    #[error(
        "IdentityProfile::mint_from_did is not yet implemented          (gated on the dig-store crate and the WU3 chain layer)"
    )]
    MintNotYetImplemented,
}

/// A `Result` specialized to this crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
