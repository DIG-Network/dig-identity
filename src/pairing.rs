//! The DID↔store bidirectional-pairing predicate, as pure types over supplied Chia records.
//!
//! A store is the authoritative profile of an identity anchor only when BOTH links hold:
//!
//! 1. **Discovery** — the store's `description` names the DID (`description == the DID string`).
//! 2. **Authority** — the store was LAUNCHED FROM the identity singleton, i.e. the store's launcher
//!    coin's PARENT is the identity singleton coin (launch-from-DID lineage — unforgeable, inherent
//!    at launch; no metadata spend, no transfer/ownership layer).
//!
//! Discovery alone is **forgeable** (anyone can put any DID in their store description), so a
//! consumer MUST require BOTH — description-only is REJECTED. WU1 supplies the predicate over
//! caller-provided records built from canonical `chia-protocol` types; WU3 wires the chain fetch
//! that populates them.

use chia_protocol::{Bytes32, Coin};

use crate::did::{parse_did_from_description, Did};

/// The record a caller supplies about a candidate profile store.
///
/// WU3 populates these fields from chain reads; WU1 only reasons over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRecord {
    /// The store's `description` field (the discovery channel — expected to be the DID string).
    pub description: String,
    /// The store's launcher coin. Its `parent_coin_info` is the authority channel (must be the
    /// identity singleton coin for launch-from-DID lineage); its `coin_id()` is the launcher id.
    pub launcher_coin: Coin,
}

impl StoreRecord {
    /// The store's launcher id (the launcher coin's id).
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_coin.coin_id()
    }
}

/// The identity anchor a store claims to belong to.
///
/// The anchor is abstracted as a singleton (a `did:chia:` DID in v1, vault-capable later); `coin_id`
/// is the specific singleton coin that must have launched the profile store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySingleton {
    /// The identity anchor's DID.
    pub did: Did,
    /// The identity singleton coin id that an authoritative store's launcher parent must equal.
    pub coin_id: Bytes32,
}

/// The result of evaluating the pairing predicate — each link reported independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingOutcome {
    /// `true` when the store description parses to a DID equal to the singleton's DID.
    pub discovery_matches: bool,
    /// `true` when the store's launcher parent equals the identity singleton coin.
    pub authority_matches: bool,
}

impl PairingOutcome {
    /// The store is the DID's authoritative profile ONLY when BOTH links hold.
    ///
    /// This is the single decision a consumer should gate on; the individual booleans exist for
    /// diagnostics (e.g. "description matched but lineage did not — likely a spoof").
    pub fn is_authoritative(self) -> bool {
        self.discovery_matches && self.authority_matches
    }
}

/// Evaluates both pairing links between `store` and `singleton`, reporting each independently.
pub fn evaluate_pairing(store: &StoreRecord, singleton: &IdentitySingleton) -> PairingOutcome {
    let discovery_matches =
        parse_did_from_description(&store.description).is_some_and(|did| did == singleton.did);
    let authority_matches = store.launcher_coin.parent_coin_info == singleton.coin_id;
    PairingOutcome {
        discovery_matches,
        authority_matches,
    }
}

/// Returns `true` iff `store` is the authoritative profile of `singleton` (BOTH links required).
///
/// The mandated consumer entry point: it is impossible to accept a store on discovery alone.
pub fn is_authoritative_profile(store: &StoreRecord, singleton: &IdentitySingleton) -> bool {
    evaluate_pairing(store, singleton).is_authoritative()
}

/// Returns `true` iff the chip35 DataLayer `store` belongs to the identity `singleton`.
///
/// The domain-named form of [`is_authoritative_profile`], answering the question consumers ask
/// verbatim — "does this store belong to this DID?". It holds IFF BOTH links of the pairing
/// predicate hold: the store's `description` names the DID (discovery) AND the store's launcher coin
/// was launched from the DID singleton (launch-from-DID lineage). Description-only or lineage-only
/// returns `false`.
///
/// **Trust boundary:** this is sound ONLY RELATIVE TO a `singleton.coin_id` the caller has resolved
/// on-chain (WU3) as `did.launcher_id`'s authentic current singleton coin. `coin_id` is caller-
/// supplied and unauthenticated here — an attacker may pass their OWN launcher coin as `coin_id` and,
/// with a store they launched from it whose description names the victim DID, obtain a `true`. Never
/// pass a producer-supplied `coin_id`.
pub fn store_belongs_to_did(store: &StoreRecord, singleton: &IdentitySingleton) -> bool {
    is_authoritative_profile(store, singleton)
}

/// A convenience bundle of the `(singleton, store)` records the pairing predicate runs over.
///
/// **NOT a self-authenticating, trustless proof.** [`StoreOwnershipProof::verify`] re-runs the §7
/// predicate — it confirms the discovery link (`store.description == did:chia:<launcher_id>`) AND the
/// authority link (`store.launcher_coin.parent_coin_info == singleton.coin_id`) — but that decision is
/// SOUND ONLY RELATIVE TO a `singleton.coin_id` the verifier has INDEPENDENTLY resolved on-chain (WU3)
/// as `did.launcher_id`'s authentic CURRENT singleton coin.
///
/// Both `singleton.did` and `singleton.coin_id` are independent, caller-supplied fields with NO
/// internal binding: nothing here checks that `coin_id` is the DID's real singleton coin. A producer
/// may therefore supply ANY `coin_id` — e.g. their own launcher coin — so a store they launched
/// themselves passes `verify()` against a victim's DID. Consuming this bundle from an UNTRUSTED
/// producer is a spoofing trap: `verify() == true` means only "these two records satisfy the
/// predicate", not "this store is chain-authenticated as the DID's profile".
///
/// The trustworthy portable proof — one whose `coin_id` is chain-bound to the DID — is WU3's job. Use
/// this type only when YOU have resolved `singleton.coin_id` on-chain yourself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOwnershipProof {
    /// The identity singleton the store claims to belong to. `coin_id` MUST be the verifier's own
    /// on-chain-resolved singleton coin for `did` (WU3) — it is NOT authenticated by [`Self::verify`].
    pub singleton: IdentitySingleton,
    /// The candidate profile store record.
    pub store: StoreRecord,
}

impl StoreOwnershipProof {
    /// Bundles a `(singleton, store)` pair. Does NOT authenticate `singleton.coin_id` — see the type
    /// doc: the caller MUST have resolved `coin_id` on-chain (WU3) before trusting [`Self::verify`].
    pub fn new(singleton: IdentitySingleton, store: StoreRecord) -> Self {
        StoreOwnershipProof { singleton, store }
    }

    /// Re-evaluates both pairing links, reporting each independently (for diagnostics).
    pub fn outcome(&self) -> PairingOutcome {
        evaluate_pairing(&self.store, &self.singleton)
    }

    /// Re-runs the §7 pairing predicate over the bundled records (BOTH links).
    ///
    /// Returns `true` iff discovery AND authority hold — but ONLY sound when `singleton.coin_id` was
    /// verifier-resolved on-chain as the DID's authentic current singleton coin (see the type doc). A
    /// `true` from an untrusted producer does NOT prove chain ownership.
    pub fn verify(&self) -> bool {
        store_belongs_to_did(&self.store, &self.singleton)
    }
}
