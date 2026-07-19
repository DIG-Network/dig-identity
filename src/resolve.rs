//! WU3 — on-chain DID resolution: from a `did:chia:` string to its **chain-authenticated** profile.
//!
//! WU1 ([`crate::pairing`], [`crate::identity_profile`]) reasons over caller-supplied records and is
//! sound only RELATIVE TO an [`IdentitySingleton`] `coin_id` the caller resolved on-chain. WU3 closes
//! that boundary: it derives everything trust-critical from the DID string itself, using a caller-
//! supplied [`ChainSource`] purely as an honest READER of chain state — never as a source of
//! authority claims.
//!
//! ## The resolution, and why each step is trust-critical
//!
//! Given only a DID string:
//!
//! 1. **Parse** the DID → its permanent `launcher_id` (canonical bech32m — [`Did::parse`]).
//! 2. **Resolve the authentic singleton coin.** Walk the DID singleton's lineage from `launcher_id`
//!    to its current unspent tip ([`ChainSource::resolve_singleton_tip`]). The tip coin's id is the
//!    ONLY value trusted as [`IdentitySingleton::coin_id`]. It is derived from the DID (via
//!    `launcher_id`), NEVER accepted from a producer — this is what defeats the authority-laundering
//!    spoof (an attacker handing you their own launcher coin + a store that merely names the victim
//!    DID in its description).
//! 3. **Discover candidate stores** whose on-chain description names the DID
//!    ([`ChainSource::find_stores_for_did`]) and keep ONLY those whose launcher parent is the authentic
//!    singleton coin from step 2 (the [`crate::pairing`] predicate — description AND launch-from-DID
//!    lineage). Zero → [`ResolveError::NoProfile`]; more than one → [`ResolveError::AmbiguousProfile`].
//! 4. **Bind the root.** Fetch the chosen store's profile content ([`ChainSource::fetch_profile`]) and
//!    require it to hash to that store's CURRENT on-chain `root_hash` — a stale/rolled-back/tampered
//!    body is [`ResolveError::StaleOrTamperedRoot`]. Only then are the profile's key slots trusted.
//!
//! The result is an [`IdentityProfile`] whose `singleton.coin_id` and `root` are both chain-derived,
//! so [`IdentityProfile::did`] / [`IdentityProfile::store_belongs_to_did`] / the resolved keys are
//! authority a consumer (dig-node's `DidSigningKeyResolver`, dig-chat, the extension, hub) can trust.
//!
//! ## Trust model of [`ChainSource`]
//!
//! The `ChainSource` MUST be the caller's OWN honest view of the chain (a full node / coinset client),
//! not an attacker-controlled channel. WU3 assumes the source reports real chain state; it does not
//! and cannot defend against a source that fabricates the chain itself. Its job is to ensure that,
//! given honest chain data, no third-party-supplied record can launder itself into DID authority.

use chia_protocol::{Bytes32, Coin};

use crate::did::Did;
use crate::identity_profile::IdentityProfile;
use crate::keys::DidKeys;
use crate::pairing::{is_authoritative_profile, IdentitySingleton, StoreRecord};
use crate::profile::Profile;

/// A candidate profile store as READ FROM CHAIN: its pairing record plus its current committed root.
///
/// The [`ChainSource`] returns one of these per store whose description names the DID being resolved.
/// `root_hash` MUST be the store singleton's CURRENT on-chain root (the source is responsible for
/// walking the store lineage to its tip); WU3 binds the fetched profile content to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStoreState {
    /// The store's pairing record (description + launcher coin) built from canonical chain types.
    pub store: StoreRecord,
    /// The store singleton's current on-chain committed profile root.
    pub root_hash: Bytes32,
}

/// A caller-supplied, honest READER of Chia chain state — the seam that keeps dig-identity chain- and
/// network-independent (so it still builds for wasm / no-network targets).
///
/// A consumer (dig-node, dig-chat, the extension, hub) implements this over its own chain backend
/// (coinset.org, a local full node, `chia-query`). WU3 supplies ALL the trust logic on top; the
/// source only fetches. See the module trust model: the source MUST be honest chain data — it is
/// never treated as a source of authority claims.
pub trait ChainSource {
    /// The source's own fetch/transport error, surfaced verbatim through [`ResolveError::Chain`].
    type Error: core::fmt::Display;

    /// Walks the singleton lineage from `launcher_id` to its current unspent tip coin.
    ///
    /// Returns `None` when the launcher never existed or the singleton has been fully spent (melted).
    /// The returned coin's id is the value WU3 trusts as the identity singleton's authentic current
    /// `coin_id` — so this MUST be a genuine lineage walk, not an echo of a caller-supplied coin.
    fn resolve_singleton_tip(&self, launcher_id: Bytes32) -> Result<Option<Coin>, Self::Error>;

    /// Returns every store whose CURRENT on-chain description names `did` (the discovery scan).
    ///
    /// Over-returning is safe: WU3 re-checks the full pairing predicate (description AND launch-from-
    /// DID lineage) against the chain-resolved singleton coin, so non-authoritative candidates are
    /// discarded. The source need not itself enforce authority.
    fn find_stores_for_did(&self, did: &Did) -> Result<Vec<ChainStoreState>, Self::Error>;

    /// Fetches the profile SMT content a store committed under `root_hash`.
    ///
    /// The returned [`Profile`] is UNTRUSTED until WU3 confirms it hashes to `root_hash`; the source
    /// only needs to return the store's current profile body (e.g. from the DataLayer store content).
    fn fetch_profile(
        &self,
        store: &StoreRecord,
        root_hash: Bytes32,
    ) -> Result<Profile, Self::Error>;
}

/// Why an on-chain DID resolution failed. Every variant fails CLOSED — a resolver never yields
/// authority it could not fully authenticate against the chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The input string is not a valid `did:chia:` DID.
    #[error("not a valid did:chia: DID")]
    InvalidDid,

    /// The DID's singleton launcher has no current unspent coin (never launched, or fully melted), so
    /// there is no authentic singleton coin to anchor authority to.
    #[error("DID singleton has no current on-chain coin (unlaunched or melted)")]
    NoIdentitySingleton,

    /// No store both names the DID AND was launched from its authentic singleton coin — the DID
    /// publishes no authoritative profile.
    #[error("no authoritative profile store found for the DID")]
    NoProfile,

    /// More than one store satisfies the pairing predicate against the DID's singleton coin; authority
    /// is ambiguous and MUST NOT be guessed.
    #[error("multiple authoritative profile stores found for the DID (ambiguous)")]
    AmbiguousProfile,

    /// The fetched profile content does not hash to the store's current on-chain root — a stale,
    /// rolled-back, or tampered body. The keys it carries are not trusted.
    #[error("profile content does not match the store's current on-chain root")]
    StaleOrTamperedRoot,

    /// The DID's authoritative profile publishes no signing public key (slot `0x0010`).
    #[error("DID profile publishes no signing public key")]
    NoSigningKey,

    /// The profile content could not be decoded / its root could not be computed.
    #[error("profile format error: {0}")]
    Format(#[from] crate::error::Error),

    /// The underlying [`ChainSource`] failed to read chain state.
    #[error("chain source error: {0}")]
    Chain(String),
}

/// Resolves a `did:chia:` DID to its **chain-authenticated** [`IdentityProfile`].
///
/// This is the trust anchor of the crate: unlike [`IdentityProfile::resolve`] (which trusts a
/// caller-supplied `coin_id`), this derives the singleton coin and the profile root from the DID via
/// `source`, so the returned profile's DID authority and keys are chain-backed. See the module docs
/// for the step-by-step guarantee. Fails closed on every ambiguity or mismatch (see [`ResolveError`]).
pub fn resolve_identity_profile<S: ChainSource>(
    did_uri: &str,
    source: &S,
) -> Result<IdentityProfile, ResolveError> {
    let did = Did::parse(did_uri).ok_or(ResolveError::InvalidDid)?;

    // The authentic singleton coin, derived from the DID (never producer-supplied).
    let tip = source
        .resolve_singleton_tip(did.launcher_id())
        .map_err(chain_error)?
        .ok_or(ResolveError::NoIdentitySingleton)?;
    let singleton = IdentitySingleton {
        did: did.clone(),
        coin_id: tip.coin_id(),
    };

    // Keep only candidates that satisfy the FULL pairing predicate against that authentic coin.
    let mut authentic = source
        .find_stores_for_did(&did)
        .map_err(chain_error)?
        .into_iter()
        .filter(|candidate| is_authoritative_profile(&candidate.store, &singleton));

    let chosen = authentic.next().ok_or(ResolveError::NoProfile)?;
    if authentic.next().is_some() {
        return Err(ResolveError::AmbiguousProfile);
    }

    // Bind the fetched profile body to the store's current on-chain root.
    let content = source
        .fetch_profile(&chosen.store, chosen.root_hash)
        .map_err(chain_error)?;
    if Bytes32::new(content.build_root()?) != chosen.root_hash {
        return Err(ResolveError::StaleOrTamperedRoot);
    }

    // Re-runs the pairing predicate on construction (already satisfied); binds the trusted root.
    Ok(IdentityProfile::resolve(singleton, chosen.store, content)?)
}

/// Resolves a DID to the cryptographic keys its authoritative profile publishes (slots `0x0010`–
/// `0x0013`), chain-authenticated end to end.
///
/// The dig-chat / dig-node resolution seam: any absent key slot is `None` (a profile may publish some
/// keys and not others), but the RESOLUTION itself fails closed — an unresolvable or spoofed DID
/// yields a [`ResolveError`], never an empty [`DidKeys`].
pub fn resolve_did_keys<S: ChainSource>(
    did_uri: &str,
    source: &S,
) -> Result<DidKeys, ResolveError> {
    Ok(resolve_identity_profile(did_uri, source)?.keys())
}

/// Resolves a DID to its Ed25519 signing public key (slot `0x0010`), chain-authenticated.
///
/// The exact seam dig-node's engine `DidSigningKeyResolver` (#1007) consumes: it returns the 32-byte
/// signing key or fails closed with [`ResolveError::NoSigningKey`] when the authoritative profile
/// publishes none — so a caller can only obtain a key that a chain-authenticated DID actually
/// published, never one attached by an unauthenticated party.
pub fn resolve_signing_key<S: ChainSource>(
    did_uri: &str,
    source: &S,
) -> Result<[u8; 32], ResolveError> {
    resolve_did_keys(did_uri, source)?
        .signing_public_key
        .ok_or(ResolveError::NoSigningKey)
}

/// Wraps a source-specific error into [`ResolveError::Chain`] without requiring `S::Error: 'static`.
fn chain_error<E: core::fmt::Display>(error: E) -> ResolveError {
    ResolveError::Chain(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::DID_CHIA_PREFIX;
    use crate::slot::standard;
    use crate::value::Value;
    use chia_sdk_utils::Address;

    /// The Ed25519 signing key a well-formed test profile publishes (slot `0x0010`).
    const SIGNING_KEY: [u8; 32] = [7u8; 32];

    /// Encodes a `did:chia:` DID string for `launcher_id` via the canonical bech32m codec.
    fn did_for(launcher_id: Bytes32) -> String {
        Address::new(launcher_id, DID_CHIA_PREFIX.to_string())
            .encode()
            .unwrap()
    }

    fn coin(parent: Bytes32) -> Coin {
        Coin::new(parent, Bytes32::new([9u8; 32]), 1)
    }

    /// A profile carrying the standard signing key, plus a display name for realism.
    fn keyed_profile() -> Profile {
        let mut profile = Profile::with_schema_v1();
        profile.set(
            standard::SIGNING_PUBLIC_KEY,
            Value::Bytes(SIGNING_KEY.to_vec()),
        );
        profile.set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()));
        profile
    }

    fn root_of(profile: &Profile) -> Bytes32 {
        Bytes32::new(profile.build_root().unwrap())
    }

    /// An in-memory honest chain view for tests: a configurable DID singleton tip, candidate stores,
    /// and the profile body returned by every `fetch_profile`.
    struct MockSource {
        tip: Option<Coin>,
        stores: Vec<ChainStoreState>,
        fetched: Profile,
        fail: Option<&'static str>,
    }

    impl MockSource {
        /// The happy path: one authoritative store launched from the DID's singleton tip.
        fn authoritative(did_uri: &str) -> (Self, Bytes32) {
            let tip = coin(Bytes32::new([1u8; 32]));
            let profile = keyed_profile();
            let store = StoreRecord {
                description: did_uri.to_string(),
                launcher_coin: coin(tip.coin_id()),
            };
            let source = MockSource {
                tip: Some(tip),
                stores: vec![ChainStoreState {
                    store,
                    root_hash: root_of(&profile),
                }],
                fetched: profile,
                fail: None,
            };
            (source, tip.coin_id())
        }
    }

    impl ChainSource for MockSource {
        type Error = &'static str;

        fn resolve_singleton_tip(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<Coin>, Self::Error> {
            match self.fail {
                Some("tip") => Err("tip fetch failed"),
                _ => Ok(self.tip),
            }
        }

        fn find_stores_for_did(&self, _did: &Did) -> Result<Vec<ChainStoreState>, Self::Error> {
            match self.fail {
                Some("stores") => Err("store scan failed"),
                _ => Ok(self.stores.clone()),
            }
        }

        fn fetch_profile(
            &self,
            _store: &StoreRecord,
            _root_hash: Bytes32,
        ) -> Result<Profile, Self::Error> {
            match self.fail {
                Some("fetch") => Err("content fetch failed"),
                _ => Ok(self.fetched.clone()),
            }
        }
    }

    #[test]
    fn resolves_keys_round_trip() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (source, _coin_id) = MockSource::authoritative(&did_uri);

        let keys = resolve_did_keys(&did_uri, &source).unwrap();
        assert_eq!(keys.signing_public_key, Some(SIGNING_KEY));
    }

    #[test]
    fn resolves_signing_key_for_engine_resolver() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (source, _) = MockSource::authoritative(&did_uri);

        assert_eq!(resolve_signing_key(&did_uri, &source).unwrap(), SIGNING_KEY);
    }

    #[test]
    fn resolved_profile_binds_chain_coin_id_and_root() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (source, coin_id) = MockSource::authoritative(&did_uri);

        let profile = resolve_identity_profile(&did_uri, &source).unwrap();
        // The singleton coin id is the chain tip, not any producer-supplied value.
        assert_eq!(profile.singleton().coin_id, coin_id);
        assert!(profile.store_belongs_to_did());
        assert_eq!(profile.root(), keyed_profile().build_root().unwrap());
    }

    #[test]
    fn invalid_did_is_rejected() {
        let (source, _) = MockSource::authoritative("not-a-did");
        assert_eq!(
            resolve_did_keys("not-a-did", &source),
            Err(ResolveError::InvalidDid)
        );
    }

    #[test]
    fn unlaunched_or_melted_singleton_is_no_identity() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (mut source, _) = MockSource::authoritative(&did_uri);
        source.tip = None;
        assert_eq!(
            resolve_identity_profile(&did_uri, &source),
            Err(ResolveError::NoIdentitySingleton)
        );
    }

    #[test]
    fn no_candidate_store_is_no_profile() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (mut source, _) = MockSource::authoritative(&did_uri);
        source.stores.clear();
        assert_eq!(
            resolve_identity_profile(&did_uri, &source),
            Err(ResolveError::NoProfile)
        );
    }

    #[test]
    fn authority_laundering_spoof_is_rejected() {
        // A store that NAMES the victim DID in its description but was launched from an ATTACKER coin
        // (not the DID's authentic singleton tip) must never resolve — the launch-from-DID lineage
        // fails, so it is discarded and the DID has no authoritative profile.
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (mut source, _) = MockSource::authoritative(&did_uri);
        let attacker_coin = coin(Bytes32::new([0xEE; 32]));
        source.stores[0].store.launcher_coin = coin(attacker_coin.coin_id());
        assert_eq!(
            resolve_identity_profile(&did_uri, &source),
            Err(ResolveError::NoProfile)
        );
    }

    #[test]
    fn store_parented_to_launcher_not_tip_is_rejected() {
        // Binding is to the resolved lineage TIP, not the raw launcher id: a store parented to an
        // earlier/stale coin is not authoritative.
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (mut source, _) = MockSource::authoritative(&did_uri);
        let did = Did::parse(&did_uri).unwrap();
        source.stores[0].store.launcher_coin = coin(did.launcher_id());
        assert_eq!(
            resolve_identity_profile(&did_uri, &source),
            Err(ResolveError::NoProfile)
        );
    }

    #[test]
    fn two_authoritative_stores_are_ambiguous() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (mut source, _) = MockSource::authoritative(&did_uri);
        let second = source.stores[0].clone();
        source.stores.push(second);
        assert_eq!(
            resolve_identity_profile(&did_uri, &source),
            Err(ResolveError::AmbiguousProfile)
        );
    }

    #[test]
    fn stale_or_tampered_root_is_rejected() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (mut source, _) = MockSource::authoritative(&did_uri);
        // Content that hashes to a DIFFERENT root than the store's committed on-chain root_hash.
        let mut tampered = keyed_profile();
        tampered.set(standard::DISPLAY_NAME, Value::Utf8("Mallory".into()));
        source.fetched = tampered;
        assert_eq!(
            resolve_identity_profile(&did_uri, &source),
            Err(ResolveError::StaleOrTamperedRoot)
        );
    }

    #[test]
    fn missing_signing_key_fails_closed() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        let (mut source, _) = MockSource::authoritative(&did_uri);
        let mut no_key = Profile::with_schema_v1();
        no_key.set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()));
        source.stores[0].root_hash = root_of(&no_key);
        source.fetched = no_key;
        assert_eq!(
            resolve_signing_key(&did_uri, &source),
            Err(ResolveError::NoSigningKey)
        );
        // resolve_did_keys still succeeds (keys are all-None); only the signing-key accessor fails.
        assert_eq!(
            resolve_did_keys(&did_uri, &source)
                .unwrap()
                .signing_public_key,
            None
        );
    }

    #[test]
    fn chain_errors_propagate_at_each_step() {
        let did_uri = did_for(Bytes32::new([42u8; 32]));
        for step in ["tip", "stores", "fetch"] {
            let (mut source, _) = MockSource::authoritative(&did_uri);
            source.fail = Some(step);
            match resolve_identity_profile(&did_uri, &source) {
                Err(ResolveError::Chain(_)) => {}
                other => panic!("step {step}: expected Chain error, got {other:?}"),
            }
        }
    }
}
