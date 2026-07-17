//! The identity-anchor identifier (a DID) and how it is discovered from a store description.
//!
//! The identity anchor is abstracted as a **singleton** so the format outlives DIDs (Chia vaults may
//! replace them later behind the same singleton outer layer). Its v1 concrete form is a Chia DID: a
//! bech32m string with the `did:chia:` prefix whose payload is the DID singleton's **launcher id**
//! (`Bytes32`). Parsing is delegated to the canonical `chia-sdk-utils` `Address` codec — never
//! hand-rolled — so a DID string byte-agrees with chip35 and the wallet SDK.
//!
//! The DID↔store DISCOVERY link is that a paired chip35 DataStore carries the DID string verbatim in
//! its `description` field (see [`crate::pairing`]).

use chia_protocol::Bytes32;
use chia_sdk_utils::Address;

/// The bech32m human-readable prefix of a v1 Chia DID (`did:chia:1...`).
pub const DID_CHIA_PREFIX: &str = "did:chia:";

/// A decentralized identifier for an identity anchor; the v1 concrete form is a Chia `did:chia:` DID.
///
/// A `Did` is only ever constructed from a string that decodes as a valid `did:chia:` bech32m
/// address, so its embedded launcher id is always available and canonical.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    text: String,
    launcher_id: Bytes32,
}

impl Did {
    /// Borrows the canonical DID string (e.g. `did:chia:1abc...`).
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The DID singleton's launcher id — its permanent identifier, decoded from the DID string.
    ///
    /// This is the stable anchor a resolver (WU3) walks to the current singleton coin; the
    /// [`crate::pairing`] authority check compares a store's launcher parent to that resolved coin.
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_id
    }

    /// Parses a DID string into a [`Did`], or `None` if it is not a valid `did:chia:` DID.
    ///
    /// The canonical constructor a chain resolver (WU3) uses to build the DID it looked up;
    /// [`parse_did_from_description`] is the same parse applied to a store's description.
    pub fn parse(did: &str) -> Option<Did> {
        parse_did_from_description(did)
    }
}

/// Parses a store `description` into the DID it names, or `None` if it is not a valid `did:chia:` DID.
///
/// The description is trimmed of surrounding whitespace first, since the discovery contract is that
/// the description IS the DID string. Validation + launcher-id extraction go through the canonical
/// bech32m `Address` codec, so an accepted string is a real, well-formed Chia DID.
pub fn parse_did_from_description(description: &str) -> Option<Did> {
    let candidate = description.trim();
    let address = Address::decode(candidate).ok()?;
    if address.prefix != DID_CHIA_PREFIX {
        return None;
    }
    Some(Did {
        text: candidate.to_string(),
        launcher_id: address.puzzle_hash,
    })
}
