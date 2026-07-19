//! Behaviour tests for the [`IdentityProfile`] primitive — the managed DID + store + SMT triple.
//!
//! These exercise the NETWORKLESS lifecycle (resolve / set / commit_root / prove_* / accessors) and
//! that the mint driver is a typed, gated stub. All records are caller-supplied (WU1 is chain-free).

use chia_sdk_utils::Address;
use dig_identity::pairing::{IdentitySingleton, SingletonLineage, StoreRecord};
use dig_identity::proof::{verify_membership, verify_non_membership};
use dig_identity::slot::standard;
use dig_identity::{Bytes32, Coin, Did, Error, IdentityProfile, Profile, Value};

// ---- fixtures ---------------------------------------------------------------------------------

const SINGLETON_COIN_ID: [u8; 32] = [0xAA; 32];
const DID_LAUNCHER: [u8; 32] = [0x22; 32];

/// A hashed-seed helper so any test-only 32-byte material is DERIVED, never an integer literal
/// (avoids the CodeQL "hard-coded cryptographic value" false positive — recurred twice).
fn derived_bytes32(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"dig-identity:test-seed:");
    h.update(label.as_bytes());
    h.finalize().into()
}

fn did_string(launcher: [u8; 32]) -> String {
    Address::new(Bytes32::from(launcher), "did:chia:".to_string())
        .encode()
        .unwrap()
}

fn singleton() -> IdentitySingleton {
    IdentitySingleton {
        did: Did::parse(&did_string(DID_LAUNCHER)).unwrap(),
        lineage: SingletonLineage::single(Bytes32::from(SINGLETON_COIN_ID)),
    }
}

/// A store launcher coin whose parent is `parent` (the authority channel).
fn launcher_coin(parent: [u8; 32]) -> Coin {
    Coin::new(Bytes32::from(parent), Bytes32::from([0x01; 32]), 1)
}

/// A store that IS the authoritative profile of `singleton()` (both pairing links hold).
fn paired_store() -> StoreRecord {
    StoreRecord {
        description: did_string(DID_LAUNCHER),
        launcher_coin: launcher_coin(SINGLETON_COIN_ID),
    }
}

fn seeded_profile() -> Profile {
    let mut p = Profile::with_schema_v2();
    p.set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()));
    p
}

// ---- resolve ----------------------------------------------------------------------------------

#[test]
fn resolve_accepts_a_paired_store_and_computes_the_root() {
    let profile = IdentityProfile::resolve(singleton(), paired_store(), seeded_profile())
        .expect("a paired store resolves");
    assert_eq!(profile.root(), seeded_profile().build_root().unwrap());
    assert!(profile.store_belongs_to_did());
    assert_eq!(profile.did(), &singleton().did);
}

#[test]
fn resolve_rejects_a_description_only_spoof() {
    // Discovery matches, but the store was NOT launched from the DID singleton (wrong parent).
    let spoof = StoreRecord {
        description: did_string(DID_LAUNCHER),
        launcher_coin: launcher_coin(derived_bytes32("attacker-parent")),
    };
    let err = IdentityProfile::resolve(singleton(), spoof, seeded_profile()).unwrap_err();
    assert_eq!(err, Error::NotAuthoritativeProfile);
}

#[test]
fn resolve_rejects_a_lineage_only_store_naming_a_different_did() {
    // Authority matches, but the description names a DIFFERENT DID.
    let spoof = StoreRecord {
        description: did_string(derived_bytes32("other-did")),
        launcher_coin: launcher_coin(SINGLETON_COIN_ID),
    };
    let err = IdentityProfile::resolve(singleton(), spoof, seeded_profile()).unwrap_err();
    assert_eq!(err, Error::NotAuthoritativeProfile);
}

// ---- set / commit_root ------------------------------------------------------------------------

#[test]
fn set_returns_the_pending_root_without_committing_it() {
    let mut profile =
        IdentityProfile::resolve(singleton(), paired_store(), seeded_profile()).unwrap();
    let committed = profile.root();

    let pending = profile
        .set(standard::BIO, Value::Utf8("hi".into()))
        .unwrap();

    // The pending root reflects the edit; the committed root is unchanged until commit_root().
    assert_ne!(pending, committed);
    assert_eq!(profile.root(), committed);

    let mut expected = seeded_profile();
    expected.set(standard::BIO, Value::Utf8("hi".into()));
    assert_eq!(pending, expected.build_root().unwrap());
}

#[test]
fn commit_root_promotes_the_pending_root() {
    let mut profile =
        IdentityProfile::resolve(singleton(), paired_store(), seeded_profile()).unwrap();
    let pending = profile
        .set(standard::BIO, Value::Utf8("hi".into()))
        .unwrap();

    let committed = profile.commit_root().unwrap();

    assert_eq!(committed, pending);
    assert_eq!(profile.root(), pending);
}

// ---- proofs (golden: proof verifies against the committed root alone) -------------------------

#[test]
fn prove_field_produces_a_membership_proof_verifying_against_the_root() {
    let profile = IdentityProfile::resolve(singleton(), paired_store(), seeded_profile()).unwrap();
    let proof = profile.prove_field(standard::DISPLAY_NAME).unwrap();
    let claim = Value::Utf8("Ada".into());
    assert!(
        verify_membership(&profile.root(), standard::DISPLAY_NAME, &claim, &proof).unwrap(),
        "the membership proof must verify against root() alone"
    );
}

#[test]
fn prove_field_absent_produces_a_non_membership_proof_verifying_against_the_root() {
    let profile = IdentityProfile::resolve(singleton(), paired_store(), seeded_profile()).unwrap();
    let proof = profile.prove_field_absent(standard::PEER_ID).unwrap();
    assert!(
        verify_non_membership(&profile.root(), standard::PEER_ID, &proof).unwrap(),
        "the non-membership proof must verify against root() alone"
    );
}

#[test]
fn prove_field_errors_for_an_absent_slot() {
    let profile = IdentityProfile::resolve(singleton(), paired_store(), seeded_profile()).unwrap();
    assert!(profile.prove_field(standard::BIO).is_err());
}

// ---- accessors --------------------------------------------------------------------------------

#[test]
fn accessors_delegate_to_the_inner_profile() {
    let mut inner = seeded_profile();
    inner.set(
        standard::XCH_ADDRESS,
        Value::Utf8(
            Address::new(Bytes32::from(derived_bytes32("pay-to")), "xch".to_string())
                .encode()
                .unwrap(),
        ),
    );
    inner.set(
        standard::PEER_ID,
        Value::Bytes(derived_bytes32("peer-id").to_vec()),
    );
    let profile = IdentityProfile::resolve(singleton(), paired_store(), inner).unwrap();

    assert_eq!(profile.display_name(), Some("Ada"));
    assert!(profile.xch_address().is_some());
    assert_eq!(profile.keys().peer_id, Some(derived_bytes32("peer-id")));
    assert_eq!(profile.singleton(), &singleton());
    assert_eq!(profile.store(), &paired_store());
    assert_eq!(profile.metadata().display_name(), Some("Ada"));
}

// ---- mint stub --------------------------------------------------------------------------------

#[test]
fn mint_from_did_is_a_typed_gated_stub() {
    let err = IdentityProfile::mint_from_did(
        launcher_coin(SINGLETON_COIN_ID),
        Bytes32::from(derived_bytes32("owner-ph")),
        seeded_profile(),
    )
    .unwrap_err();
    assert_eq!(err, Error::MintNotYetImplemented);
}
