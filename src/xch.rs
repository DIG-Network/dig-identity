//! The canonical mainnet XCH receive-address profile field (slot `0x0008`).
//!
//! An identity may publish an XCH receive address so a peer can tip or pay it — the $DIG North Star
//! payments seam ([`crate::slot::standard::XCH_ADDRESS`]). The value is the bech32m address STRING
//! (`xch1…`, stored `Utf8`), but a reader MUST NOT trust it blindly: an address is only accepted
//! when it decodes as a **canonical mainnet XCH address** — the human-readable prefix is exactly
//! `xch`, the Bech32m checksum verifies, and the payload is a 32-byte puzzle hash. Validation is
//! delegated to the canonical `chia-sdk-utils` `Address` codec (the same codec [`crate::did`] uses),
//! never hand-rolled, so an accepted address byte-agrees with the wallet SDK.

use chia_sdk_utils::Address;

/// The bech32m human-readable prefix of a canonical mainnet XCH address (`xch1…`).
///
/// Mainnet only — a `txch` (testnet) address has a different prefix and is rejected.
pub const XCH_ADDRESS_HRP: &str = "xch";

/// Validates and canonicalizes an XCH receive-address string, or `None` if it is not a canonical
/// mainnet XCH address.
///
/// The input is trimmed, then decoded through the canonical bech32m `Address` codec, which enforces
/// the Bech32m checksum and a 32-byte payload. It is accepted only when its prefix is exactly `xch`.
/// A wrong HRP (e.g. `txch`, `xch1`-lookalike, or a `did:chia:` string), a bad checksum, or a
/// non-32-byte payload all yield `None`. The returned string is the trimmed, verified address.
pub fn parse_xch_address(address: &str) -> Option<String> {
    let candidate = address.trim();
    let decoded = Address::decode(candidate).ok()?;
    if decoded.prefix != XCH_ADDRESS_HRP {
        return None;
    }
    Some(candidate.to_string())
}

/// Returns `true` iff `address` is a canonical mainnet XCH address (see [`parse_xch_address`]).
pub fn is_valid_xch_address(address: &str) -> bool {
    parse_xch_address(address).is_some()
}
