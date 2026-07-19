//! The DID<->store bidirectional-pairing predicate, as pure types over supplied Chia records.
//!
//! A store is the authoritative profile of an identity anchor only when BOTH links hold:
//!
//! 1. **Discovery** -- the store's `description` names the DID (`description == the DID string`).
//! 2. **Authority** -- the store was LAUNCHED FROM the identity singleton, i.e. the store's launcher
//!    coin's PARENT is a genuine coin IN THE DID SINGLETON'S LINEAGE (launch-from-DID lineage --
//!    unforgeable, inherent at launch; no metadata spend, no transfer/ownership layer).
//!
//! ## Why authority is lineage MEMBERSHIP, not tip EQUALITY
//!
//! A store (or NFT) launched from a DID parents its launcher coin to the DID coin AS IT EXISTED AT
//! SPEND TIME (`Cn`), and that SAME spend RECREATES the DID singleton, advancing it to `Cn+1`
//! (chip35's `IntermediateLauncher::new(did.coin.coin_id(), ..)` + `did.update`). So the launcher's
//! parent is `Cn` while the singleton's CURRENT tip is already `Cn+1` -- they never match. Binding
//! authority to `== tip` would therefore reject EVERY legitimately-launched profile store. Authority
//! is instead MEMBERSHIP: the launcher's parent must be a genuine coin in the DID singleton's lineage
//! (launcher -> tip inclusive). This keeps the security property -- producing ANY coin in the victim
//! DID's lineage requires the victim's key, so an attacker's coin is never a member and the link stays
//! unforgeable -- while accepting a store parented to ANY historical DID coin.
//!
//! Discovery alone is **forgeable** (anyone can put any DID in their store description), so a
//! consumer MUST require BOTH links -- description-only is REJECTED. WU1 supplies the predicate over
//! caller-provided records built from canonical `chia-protocol` types; WU3 wires the chain fetch that
//! populates the lineage (a walk from the DID launcher to its current tip).

use std::collections::BTreeSet;

use chia_protocol::{Bytes32, Coin};

use crate::did::{parse_did_from_description, Did};

/// The record a caller supplies about a candidate profile store.
///
/// WU3 populates these fields from chain reads; WU1 only reasons over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRecord {
    /// The store's `description` field (the discovery channel -- expected to be the DID string).
    pub description: String,
    /// The store's launcher coin. Its `parent_coin_info` is the authority channel (must be a coin in
    /// the identity singleton's lineage for launch-from-DID lineage); its `coin_id()` is the
    /// launcher id.
    pub launcher_coin: Coin,
}

impl StoreRecord {
    /// The store's launcher id (the launcher coin's id).
    pub fn launcher_id(&self) -> Bytes32 {
        self.launcher_coin.coin_id()
    }
}

/// The lineage of a DID identity singleton: every coin id from the launcher spend forward to the
/// current unspent tip.
///
/// Authority is MEMBERSHIP in this lineage, not equality with the tip (see the module docs): a store
/// launched from ANY genuine DID coin -- the launch-time coin `Cn`, later spent to `Cn+1` -- is
/// authoritative, while an attacker's coin (never a member, since minting any lineage coin requires
/// the DID's key) is not. A conforming WU3 [`crate::resolve::ChainSource`] populates this by walking
/// the singleton lineage on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingletonLineage {
    /// The current unspent singleton tip coin id (the DID's current on-chain state handle).
    tip: Bytes32,
    /// Every coin id in the lineage (launcher -> tip inclusive). Always contains `tip`.
    members: BTreeSet<Bytes32>,
}

impl SingletonLineage {
    /// Builds a lineage from its full member set and current `tip`. `tip` is always treated as a
    /// member, so a caller need not include it in `members` explicitly.
    pub fn new(tip: Bytes32, members: impl IntoIterator<Item = Bytes32>) -> Self {
        let mut members: BTreeSet<Bytes32> = members.into_iter().collect();
        members.insert(tip);
        Self { tip, members }
    }

    /// A degenerate single-coin lineage (the tip is the only member).
    ///
    /// Use ONLY for a DID that has never been spent since launch, or where the caller genuinely knows
    /// no other lineage coin. It reproduces the strict tip-only authority behaviour, so a store
    /// parented to an earlier coin will NOT match -- prefer [`Self::new`] with the walked lineage.
    pub fn single(tip: Bytes32) -> Self {
        Self::new(tip, [tip])
    }

    /// The current unspent singleton tip coin id.
    pub fn tip(&self) -> Bytes32 {
        self.tip
    }

    /// Whether `coin_id` is a genuine coin in this singleton's lineage -- the authority membership test.
    pub fn contains(&self, coin_id: Bytes32) -> bool {
        self.members.contains(&coin_id)
    }
}

/// The identity anchor a store claims to belong to.
///
/// The anchor is abstracted as a singleton (a `did:chia:` DID in v1, vault-capable later); `lineage`
/// is the singleton's coin lineage, one member of which an authoritative store's launcher parent must
/// equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySingleton {
    /// The identity anchor's DID.
    pub did: Did,
    /// The identity singleton's lineage (launcher -> tip). An authoritative store's launcher parent
    /// must be a MEMBER of this lineage (launched from SOME genuine DID coin), never merely the tip.
    pub lineage: SingletonLineage,
}

impl IdentitySingleton {
    /// The identity singleton's current unspent tip coin id (its current on-chain state handle).
    pub fn coin_id(&self) -> Bytes32 {
        self.lineage.tip()
    }
}

/// The result of evaluating the pairing predicate -- each link reported independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingOutcome {
    /// `true` when the store description parses to a DID equal to the singleton's DID.
    pub discovery_matches: bool,
    /// `true` when the store's launcher parent is a member of the identity singleton's lineage.
    pub authority_matches: bool,
}

impl PairingOutcome {
    /// The store is the DID's authoritative profile ONLY when BOTH links hold.
    ///
    /// This is the single decision a consumer should gate on; the individual booleans exist for
    /// diagnostics (e.g. "description matched but lineage did not -- likely a spoof").
    pub fn is_authoritative(self) -> bool {
        self.discovery_matches && self.authority_matches
    }
}

/// Evaluates both pairing links between `store` and `singleton`, reporting each independently.
pub fn evaluate_pairing(store: &StoreRecord, singleton: &IdentitySingleton) -> PairingOutcome {
    let discovery_matches =
        parse_did_from_description(&store.description).is_some_and(|did| did == singleton.did);
    let authority_matches = singleton
        .lineage
        .contains(store.launcher_coin.parent_coin_info);
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
/// verbatim -- "does this store belong to this DID?". It holds IFF BOTH links of the pairing
/// predicate hold: the store's `description` names the DID (discovery) AND the store's launcher coin
/// was launched from a coin in the DID singleton's lineage (launch-from-DID lineage). Description-only
/// or lineage-only returns `false`.
///
/// **Trust boundary:** this is sound ONLY RELATIVE TO a `singleton.lineage` the caller has resolved
/// on-chain (WU3) as `did.launcher_id`'s authentic singleton lineage. `lineage` is caller-supplied and
/// unauthenticated here -- an attacker may pass their OWN singleton's lineage and, with a store they
/// launched from it whose description names the victim DID, obtain a `true`. Never pass a
/// producer-supplied `lineage`.
pub fn store_belongs_to_did(store: &StoreRecord, singleton: &IdentitySingleton) -> bool {
    is_authoritative_profile(store, singleton)
}

/// A convenience bundle of the `(singleton, store)` records the pairing predicate runs over.
///
/// **NOT a self-authenticating, trustless proof.** [`StoreOwnershipProof::verify`] re-runs the section 7
/// predicate -- it confirms the discovery link (`store.description == did:chia:<launcher_id>`) AND the
/// authority link (`store.launcher_coin.parent_coin_info` is a member of `singleton.lineage`) -- but
/// that decision is SOUND ONLY RELATIVE TO a `singleton.lineage` the verifier has INDEPENDENTLY
/// resolved on-chain (WU3) as `did.launcher_id`'s authentic singleton lineage.
///
/// Both `singleton.did` and `singleton.lineage` are independent, caller-supplied fields with NO
/// internal binding: nothing here checks that `lineage` is the DID's real singleton lineage. A producer
/// may therefore supply ANY lineage -- e.g. their own singleton's -- so a store they launched
/// themselves passes `verify()` against a victim's DID. Consuming this bundle from an UNTRUSTED
/// producer is a spoofing trap: `verify() == true` means only "these two records satisfy the
/// predicate", not "this store is chain-authenticated as the DID's profile".
///
/// The trustworthy portable proof -- one whose `lineage` is chain-bound to the DID -- is WU3's job. Use
/// this type only when YOU have resolved `singleton.lineage` on-chain yourself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOwnershipProof {
    /// The identity singleton the store claims to belong to. `lineage` MUST be the verifier's own
    /// on-chain-resolved singleton lineage for `did` (WU3) -- it is NOT authenticated by [`Self::verify`].
    pub singleton: IdentitySingleton,
    /// The candidate profile store record.
    pub store: StoreRecord,
}

impl StoreOwnershipProof {
    /// Bundles a `(singleton, store)` pair. Does NOT authenticate `singleton.lineage` -- see the type
    /// doc: the caller MUST have resolved `lineage` on-chain (WU3) before trusting [`Self::verify`].
    pub fn new(singleton: IdentitySingleton, store: StoreRecord) -> Self {
        StoreOwnershipProof { singleton, store }
    }

    /// Re-evaluates both pairing links, reporting each independently (for diagnostics).
    pub fn outcome(&self) -> PairingOutcome {
        evaluate_pairing(&self.store, &self.singleton)
    }

    /// Re-runs the section 7 pairing predicate over the bundled records (BOTH links).
    ///
    /// Returns `true` iff discovery AND authority hold -- but ONLY sound when `singleton.lineage` was
    /// verifier-resolved on-chain as the DID's authentic singleton lineage (see the type doc). A
    /// `true` from an untrusted producer does NOT prove chain ownership.
    pub fn verify(&self) -> bool {
        store_belongs_to_did(&self.store, &self.singleton)
    }
}
