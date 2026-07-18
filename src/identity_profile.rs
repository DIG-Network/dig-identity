//! The [`IdentityProfile`] primitive — the managed DIG Network "Profile" object.
//!
//! A DIG identity, at rest, is three things that must agree: a **DID identity singleton** (its
//! anchor), the **chip35 DataLayer store** launched from that DID (which holds the profile), and the
//! **profile SMT** ([`Profile`]) the store commits to via a 32-byte root. [`IdentityProfile`] is the
//! managed object composing them into one lifecycle — the type dig-chat / dig-email /
//! dig-video-chat and dig-app profiles build on, rather than re-assembling the triple by hand.
//!
//! It is a THIN, honest composition over the crate's already-sound pieces — the [`Profile`] SMT,
//! the [`crate::pairing`] predicate, and the [`crate::proof`] verifiers. It ADDS only lifecycle
//! wiring (resolve / edit / commit / prove as one object); it invents no new trust.
//!
//! ## Layering vs [`Profile`]
//!
//! [`Profile`] is the metadata SMT slot-map and stays exactly as it was (dig-app consumes it
//! directly). `IdentityProfile` *wraps* a `Profile` together with the DID↔store binding — it does
//! NOT replace it.
//!
//! ## Trust boundary (load-bearing)
//!
//! [`IdentityProfile::resolve`] enforces the DID↔store pairing predicate over the CALLER-SUPPLIED
//! records, exactly as [`crate::pairing::store_belongs_to_did`] does — and inherits its trust
//! boundary verbatim: the predicate is sound ONLY RELATIVE TO an [`IdentitySingleton`] `coin_id` the
//! caller has independently resolved on-chain (WU3) as the DID's authentic current singleton coin.
//! `resolve` does NOT authenticate `coin_id`; it will not launder a producer-supplied coin id into
//! apparent authority. A successful `resolve` means "these records satisfy the pairing predicate",
//! NOT "this store is chain-authenticated as the DID's profile". Never pass a producer-supplied
//! `coin_id`.

use chia_protocol::{Bytes32, Coin};

use crate::did::Did;
use crate::error::{Error, Result};
use crate::keys::DidKeys;
use crate::pairing::{store_belongs_to_did, IdentitySingleton, StoreRecord};
use crate::profile::Profile;
use crate::proof::ProfileProof;
use crate::slot::SlotId;
use crate::value::Value;

/// The managed DIG identity profile: a DID identity paired with its chip35 store and profile SMT.
///
/// Construct via [`IdentityProfile::resolve`] (which rejects an unpaired/spoofed store) — never by
/// field literal. The retained `root` is the **committed** metadata root (equal to the on-chain
/// store root when synced); edits via [`IdentityProfile::set`] are pending until
/// [`IdentityProfile::commit_root`] promotes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProfile {
    /// The identity anchor: the DID plus the caller-resolved singleton coin id (see the trust
    /// boundary in the module docs — `coin_id` is NOT authenticated here).
    singleton: IdentitySingleton,
    /// The paired chip35 DataLayer store record (launch-from-DID lineage).
    store: StoreRecord,
    /// The profile metadata SMT slot-map.
    metadata: Profile,
    /// The committed metadata root — equal to `metadata.build_root()` at construction and after
    /// each [`Self::commit_root`]; unchanged by a pending [`Self::set`].
    root: [u8; 32],
}

impl IdentityProfile {
    /// Resolves a paired identity profile from caller-supplied records, or fails if the store is not
    /// the DID's authoritative profile.
    ///
    /// Enforces the [`crate::pairing`] predicate on construction: the `store` must both name
    /// `singleton`'s DID in its description AND have been launched from the singleton coin. A
    /// description-only or lineage-only store is a spoof and is REJECTED with
    /// [`Error::NotAuthoritativeProfile`] — so an `IdentityProfile` value can only exist for a store
    /// that satisfies the predicate. The committed [`Self::root`] is computed from `metadata`.
    ///
    /// See the module-level trust boundary: this is sound only relative to a `singleton.coin_id` the
    /// caller resolved on-chain (WU3); `resolve` does not authenticate it.
    pub fn resolve(
        singleton: IdentitySingleton,
        store: StoreRecord,
        metadata: Profile,
    ) -> Result<Self> {
        if !store_belongs_to_did(&store, &singleton) {
            return Err(Error::NotAuthoritativeProfile);
        }
        let root = metadata.build_root()?;
        Ok(Self {
            singleton,
            store,
            metadata,
            root,
        })
    }

    /// Mints a brand-new identity profile: launches a DID and a chip35 store launched from it, seeded
    /// with `seed_metadata`. **NOT YET IMPLEMENTED** — always returns [`Error::MintNotYetImplemented`].
    ///
    /// Minting builds on-chain spends and is GATED on the dig-store crate (#703/#754) and the WU3
    /// chain layer (#778). dig-identity MUST NOT depend on dig-store (the dependency graph stays
    /// acyclic), so the launch driver ships as a WU2 follow-on rather than here. The signature is
    /// present now so consumers can code against the primitive's final shape; when the gate lifts it
    /// will also yield the launch `SpendBundle` (and take the owner delegation) alongside `Self`.
    pub fn mint_from_did(
        _did_coin: Coin,
        _owner_puzzle_hash: Bytes32,
        _seed_metadata: Profile,
    ) -> Result<Self> {
        Err(Error::MintNotYetImplemented)
    }

    /// Sets a profile slot to a value and returns the resulting **pending** metadata root.
    ///
    /// The edit is applied to the in-memory metadata immediately, but the committed [`Self::root`]
    /// (which tracks the on-chain store root) is left unchanged until [`Self::commit_root`] promotes
    /// it — so a caller can compute the root a future on-chain update WOULD commit without yet
    /// claiming it as current.
    pub fn set(&mut self, slot: SlotId, value: Value) -> Result<[u8; 32]> {
        self.metadata.set(slot, value);
        self.metadata.build_root()
    }

    /// Promotes the current metadata into the committed [`Self::root`] and returns it.
    ///
    /// This is the root a caller then commits on-chain. Building and broadcasting the chip35
    /// update-root spend is the WU2/WU3 chain layer's job — networkless WU1 only computes the root.
    pub fn commit_root(&mut self) -> Result<[u8; 32]> {
        self.root = self.metadata.build_root()?;
        Ok(self.root)
    }

    /// Returns `true` iff the paired store belongs to the identity singleton (the pairing predicate).
    ///
    /// Always `true` for a value produced by [`Self::resolve`] (which enforces it) — retained as an
    /// explicit, re-checkable statement of the invariant at the call site. Carries the same trust
    /// boundary as [`store_belongs_to_did`] (see the module docs).
    pub fn store_belongs_to_did(&self) -> bool {
        store_belongs_to_did(&self.store, &self.singleton)
    }

    /// Builds a membership proof that `slot` currently holds its value, verifiable against
    /// [`Self::root`] by [`crate::proof::verify_membership`]. Errors if `slot` is absent.
    pub fn prove_field(&self, slot: SlotId) -> Result<ProfileProof> {
        self.metadata.build_tree()?.prove_membership(slot)
    }

    /// Builds a non-membership proof that `slot` is currently absent, verifiable against
    /// [`Self::root`] by [`crate::proof::verify_non_membership`]. Errors if `slot` is present.
    pub fn prove_field_absent(&self, slot: SlotId) -> Result<ProfileProof> {
        self.metadata.build_tree()?.prove_non_membership(slot)
    }

    /// The identity anchor's DID.
    pub fn did(&self) -> &Did {
        &self.singleton.did
    }

    /// The identity singleton (DID + caller-resolved coin id).
    pub fn singleton(&self) -> &IdentitySingleton {
        &self.singleton
    }

    /// The paired chip35 DataLayer store record.
    pub fn store(&self) -> &StoreRecord {
        &self.store
    }

    /// The profile metadata SMT slot-map (for any accessor not surfaced directly here).
    pub fn metadata(&self) -> &Profile {
        &self.metadata
    }

    /// The committed metadata root (equal to the on-chain store root when synced).
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The DID's published cryptographic keys, resolved from the standard key slots.
    pub fn keys(&self) -> DidKeys {
        self.metadata.resolve_keys()
    }

    /// The published XCH receive address (`xch1…`), if present and canonical — the $DIG-payments seam.
    pub fn xch_address(&self) -> Option<&str> {
        self.metadata.xch_address()
    }

    /// The display name, if present.
    pub fn display_name(&self) -> Option<&str> {
        self.metadata.display_name()
    }
}
