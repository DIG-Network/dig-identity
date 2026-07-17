//! Composed "this profile datum belongs to this DID" verification — THE consumer seam.
//!
//! dig-chat, the hub, and the extension all ask one question: *does this profile field belong to
//! DID D?* Answering it soundly is TWO independent checks that MUST both hold:
//!
//! 1. **Pairing** — the supplied store is the DID's authoritative profile (its `description` names
//!    the DID AND it was launched from the DID singleton; see [`crate::pairing`]). Discovery alone is
//!    forgeable, so this rejects a spoofed store.
//! 2. **Membership** — the claimed `(slot, value)` (or the claimed ABSENCE of a slot) is proven
//!    against that store's authoritative profile `root` by a merkle proof (see [`crate::proof`]).
//!
//! These functions COMPOSE the already-gated primitives — they add no new trust, only the AND. They
//! are **accept-only**: `Ok(true)` means "accepted", and any failure is an explicit [`Error`]
//! ([`Error::NotAuthoritativeProfile`] or [`Error::FieldProofRejected`]) rather than a silent
//! `Ok(false)` a caller might forget to check — so `?`-ing the result is a sound "verify or bail".
//!
//! WU1 is networkless: the caller supplies the authoritative `root` and the store records. Fetching
//! the on-chain profile root and resolving the DID's current singleton coin is WU3.

use crate::error::{Error, Result};
use crate::pairing::{store_belongs_to_did, IdentitySingleton, StoreRecord};
use crate::proof::{verify_membership, verify_non_membership, ProfileProof};
use crate::slot::SlotId;
use crate::value::Value;

/// Verifies that `(slot, value)` is a datum of `singleton`'s authoritative profile.
///
/// Accepts (returns `Ok(true)`) IFF BOTH hold: `store` belongs to `singleton` (pairing predicate)
/// AND `proof` proves `slot` holds `value` in the profile committed to by `root`. Any other case is
/// a non-verification — NOT an acceptance — surfaced as an [`Error`]:
///
/// - [`Error::NotAuthoritativeProfile`] — the store is not the DID's authoritative profile.
/// - [`Error::FieldProofRejected`] — the field's merkle proof did not verify against `root`.
///
/// **Trust boundary:** both inputs the caller supplies are unauthenticated here and MUST be
/// independently resolved on-chain (WU3): `singleton.coin_id` MUST be the DID's authentic current
/// singleton coin (see [`store_belongs_to_did`] — a producer-supplied `coin_id` is spoofable), and
/// `root` MUST be THIS store's authentic current on-chain `root_hash`. A valid membership proof
/// against an unrelated `root` gives a false accept, exactly as a wrong `coin_id` does.
pub fn verify_profile_field_for_did(
    singleton: &IdentitySingleton,
    store: &StoreRecord,
    root: &[u8; 32],
    slot: SlotId,
    value: &Value,
    proof: &ProfileProof,
) -> Result<bool> {
    if !store_belongs_to_did(store, singleton) {
        return Err(Error::NotAuthoritativeProfile);
    }
    if !verify_membership(root, slot, value, proof)? {
        return Err(Error::FieldProofRejected);
    }
    Ok(true)
}

/// Verifies that `singleton`'s authoritative profile has NO value at `slot`.
///
/// The non-membership counterpart of [`verify_profile_field_for_did`]: accepts (`Ok(true)`) IFF the
/// `store` belongs to `singleton` AND `proof` proves `slot` is absent from the profile committed to
/// by `root`. This lets a consumer soundly conclude "DID D publishes no value at this slot" (e.g.
/// dig-chat distinguishing "no encryption key" from a present one). Failure modes mirror
/// [`verify_profile_field_for_did`].
pub fn verify_profile_field_absent_for_did(
    singleton: &IdentitySingleton,
    store: &StoreRecord,
    root: &[u8; 32],
    slot: SlotId,
    proof: &ProfileProof,
) -> Result<bool> {
    if !store_belongs_to_did(store, singleton) {
        return Err(Error::NotAuthoritativeProfile);
    }
    if !verify_non_membership(root, slot, proof)? {
        return Err(Error::FieldProofRejected);
    }
    Ok(true)
}
