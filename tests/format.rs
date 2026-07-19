//! Golden + round-trip conformance tests for the dig-identity WU1 format layer.
//!
//! These are the spec's executable proof: value encoding KATs, slot-key determinism, membership and
//! non-membership proof round-trips, tamper/replay rejection, older-schema reads, and the
//! bidirectional-pairing predicate. Together they pin the byte-level contract a second (JS/wasm)
//! implementation must reproduce.

use dig_identity::did::parse_did_from_description;
use dig_identity::pairing::{
    evaluate_pairing, is_authoritative_profile, IdentitySingleton, SingletonLineage, StoreRecord,
};
use dig_identity::proof::{verify_membership, verify_non_membership};
use dig_identity::slot::{standard, SlotId};
use dig_identity::value::Value;
use dig_identity::{Did, Profile, ProfileTree};

// ---------- value encoding KATs ----------

#[test]
fn utf8_value_encodes_to_tag_len_bytes() {
    // "hi" -> tag 0x01, len 0x00000002, payload "hi"
    let encoded = Value::Utf8("hi".into()).encode();
    assert_eq!(encoded, vec![0x01, 0x00, 0x00, 0x00, 0x02, b'h', b'i']);
}

#[test]
fn fixed_width_values_encode_big_endian() {
    assert_eq!(Value::U16(1).encode(), vec![0x03, 0, 0, 0, 2, 0x00, 0x01]);
    assert_eq!(
        Value::U32(0x0102_0304).encode(),
        vec![0x04, 0, 0, 0, 4, 0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(
        Value::U64(1).encode(),
        vec![0x05, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1]
    );
}

#[test]
fn every_value_kind_round_trips() {
    for value in [
        Value::Utf8("Ada Lovelace 💠".into()),
        Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        Value::U16(0xABCD),
        Value::U32(0xDEAD_BEEF),
        Value::U64(0x0123_4567_89AB_CDEF),
    ] {
        let decoded = Value::decode(&value.encode()).expect("round trip");
        assert_eq!(decoded, value);
    }
}

#[test]
fn decode_rejects_unknown_tag() {
    let blob = vec![0x7f, 0, 0, 0, 0];
    assert!(matches!(
        Value::decode(&blob),
        Err(dig_identity::Error::UnknownTag(0x7f))
    ));
}

#[test]
fn decode_rejects_length_mismatch() {
    // declares 4 payload bytes but supplies 2
    let blob = vec![0x02, 0, 0, 0, 4, 0xaa, 0xbb];
    assert!(matches!(
        Value::decode(&blob),
        Err(dig_identity::Error::LengthMismatch { .. })
    ));
}

#[test]
fn decode_rejects_truncated_header() {
    assert!(matches!(
        Value::decode(&[0x01, 0x00]),
        Err(dig_identity::Error::TruncatedValue(_))
    ));
}

#[test]
fn decode_rejects_wrong_fixed_width() {
    // U16 tag but 3 payload bytes (length prefix agrees, fixed-width check fails)
    let blob = vec![0x03, 0, 0, 0, 3, 0x00, 0x01, 0x02];
    assert!(matches!(
        Value::decode(&blob),
        Err(dig_identity::Error::WrongWidth { expected: 2, .. })
    ));
}

// ---------- slot-key derivation ----------

#[test]
fn slot_key_is_deterministic_and_distinct() {
    assert_eq!(standard::DISPLAY_NAME.key(), SlotId(0x0001).key());
    assert_ne!(standard::DISPLAY_NAME.key(), standard::BIO.key());
}

#[test]
fn slot_key_matches_documented_preimage() {
    // sha256("dig-identity:slot:" ‖ u32_be(0x0001))
    let mut preimage = b"dig-identity:slot:".to_vec();
    preimage.extend_from_slice(&1u32.to_be_bytes());
    let expected = dig_identity::hash::sha256(&preimage);
    assert_eq!(standard::DISPLAY_NAME.key(), expected);
}

#[test]
fn reserved_ranges_classify_correctly() {
    assert!(SlotId(0x0000).is_future_standard());
    assert!(SlotId(0x0100).is_ecosystem_extension());
    assert!(SlotId(0x1000).is_custom());
    assert!(SlotId(0xF000).is_encrypted_reserved());
    assert!(!SlotId(0x1000).is_encrypted_reserved());
}

// ---------- membership / non-membership proof round-trips ----------

fn sample_tree() -> (ProfileTree, [u8; 32]) {
    let mut profile = Profile::with_schema_v2();
    profile
        .set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()))
        .set(standard::BIO, Value::Utf8("mathematician".into()))
        .set(standard::BLS_G1_PUBLIC_KEY, Value::Bytes(vec![7u8; 48]));
    let tree = profile.build_tree().unwrap();
    let root = tree.root();
    (tree, root)
}

#[test]
fn membership_proof_verifies_against_root_alone() {
    let (tree, root) = sample_tree();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
    let claim = Value::Utf8("Ada".into());
    assert!(verify_membership(&root, standard::DISPLAY_NAME, &claim, &proof).unwrap());
}

#[test]
fn membership_proof_rejects_tampered_value() {
    let (tree, root) = sample_tree();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
    let forged = Value::Utf8("Mallory".into());
    assert!(!verify_membership(&root, standard::DISPLAY_NAME, &forged, &proof).unwrap());
}

#[test]
fn membership_proof_rejects_cross_slot_replay() {
    // A proof minted for DISPLAY_NAME must not verify a claim about BIO.
    let (tree, root) = sample_tree();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
    let claim = Value::Utf8("Ada".into());
    assert!(!verify_membership(&root, standard::BIO, &claim, &proof).unwrap());
}

#[test]
fn proof_survives_serialization_round_trip() {
    use dig_identity::ProfileProof;
    let (tree, root) = sample_tree();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
    let wire = proof.as_bytes().to_vec();
    let restored = ProfileProof::from_bytes(wire);
    let claim = Value::Utf8("Ada".into());
    assert!(verify_membership(&root, standard::DISPLAY_NAME, &claim, &restored).unwrap());
}

#[test]
fn tree_exposes_encoded_bytes_and_profile_iterates_in_order() {
    let (tree, _) = sample_tree();
    let encoded = tree.get_encoded(standard::DISPLAY_NAME).unwrap().unwrap();
    assert_eq!(Value::decode(&encoded).unwrap(), Value::Utf8("Ada".into()));
    assert!(tree.get_encoded(standard::LOCATION).unwrap().is_none());

    let mut profile = Profile::new();
    profile
        .set(standard::BIO, Value::Utf8("b".into()))
        .set(standard::DISPLAY_NAME, Value::Utf8("a".into()));
    let ordered: Vec<_> = profile.iter().map(|(slot, _)| *slot).collect();
    assert_eq!(ordered, vec![standard::DISPLAY_NAME, standard::BIO]);
    assert_eq!(
        profile.build_root().unwrap(),
        profile.build_tree().unwrap().root()
    );
}

#[test]
fn non_membership_proof_verifies_absent_slot() {
    let (tree, root) = sample_tree();
    let proof = tree.prove_non_membership(standard::PEER_ID).unwrap();
    assert!(verify_non_membership(&root, standard::PEER_ID, &proof).unwrap());
}

#[test]
fn non_membership_proof_rejects_present_slot() {
    // A slot that IS present must not verify as absent using its own proof.
    let (tree, root) = sample_tree();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
    assert!(!verify_non_membership(&root, standard::DISPLAY_NAME, &proof).unwrap());
}

#[test]
fn prove_membership_errors_on_absent_slot() {
    let (tree, _) = sample_tree();
    assert!(tree.prove_membership(standard::PEER_ID).is_err());
}

#[test]
fn prove_non_membership_errors_on_present_slot() {
    let (tree, _) = sample_tree();
    assert!(tree.prove_non_membership(standard::DISPLAY_NAME).is_err());
}

#[test]
fn removing_a_slot_makes_it_provably_absent() {
    let mut profile = Profile::new();
    profile.set(standard::LOCATION, Value::Utf8("London".into()));
    let mut tree = profile.build_tree().unwrap();
    assert!(tree.get(standard::LOCATION).unwrap().is_some());

    tree.remove(standard::LOCATION).unwrap();
    let root = tree.root();
    let proof = tree.prove_non_membership(standard::LOCATION).unwrap();
    assert!(verify_non_membership(&root, standard::LOCATION, &proof).unwrap());
}

#[test]
fn empty_tree_has_zero_root() {
    assert_eq!(ProfileTree::new().root(), [0u8; 32]);
}

// ---------- profile reads + older-schema compatibility ----------

#[test]
fn profile_accessors_decode_standard_slots() {
    let mut profile = Profile::with_schema_v2();
    profile
        .set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()))
        .set(standard::BIO, Value::Utf8("bio".into()))
        .set(standard::BLS_G1_PUBLIC_KEY, Value::Bytes(vec![9u8; 48]))
        .set(standard::KEY_EPOCH, Value::U32(3));

    assert_eq!(profile.schema_version(), Some(2));
    assert_eq!(profile.display_name(), Some("Ada"));
    assert_eq!(profile.bio(), Some("bio"));

    let keys = dig_identity::resolve_did_keys(&profile);
    assert_eq!(keys.bls_g1_public_key, Some([9u8; 48]));
    assert_eq!(keys.peer_id, None);
    assert_eq!(keys.key_epoch, Some(3));
}

#[test]
fn resolve_keys_ignores_a_wrong_length_identity_key() {
    // Slot 0x0010 must hold exactly 48 bytes to be read as a BLS G1 key; a 32-byte value (e.g. a
    // stale v1 Ed25519 key) is treated as absent, so a consumer never receives a malformed key.
    let mut profile = Profile::with_schema_v2();
    profile.set(standard::BLS_G1_PUBLIC_KEY, Value::Bytes(vec![1u8; 32]));
    assert_eq!(
        dig_identity::resolve_did_keys(&profile).bls_g1_public_key,
        None
    );
}

#[test]
fn reader_ignores_an_unknown_future_slot() {
    // A profile with an UNKNOWN future custom slot must still read cleanly: known slots decode, the
    // unknown slot is simply ignored by the typed accessors (additive-only, §2.4).
    let mut profile = Profile::with_schema_v2();
    profile
        .set(standard::DISPLAY_NAME, Value::Utf8("Grace".into()))
        .set(SlotId(0x1234), Value::Bytes(vec![1, 2, 3])); // custom/unknown slot

    let tree = profile.build_tree().unwrap();
    let root = tree.root();

    assert_eq!(profile.schema_version(), Some(2));
    assert_eq!(profile.display_name(), Some("Grace"));

    // The unknown slot still participates in the tree and is itself provable.
    let proof = tree.prove_membership(SlotId(0x1234)).unwrap();
    assert!(
        verify_membership(&root, SlotId(0x1234), &Value::Bytes(vec![1, 2, 3]), &proof).unwrap()
    );
}

// ---------- DID parsing (canonical did:chia: bech32m) ----------

use chia_sdk_utils::Address;
use dig_identity::{Bytes32, Coin};

/// Encodes a launcher id as its canonical `did:chia:1...` DID string.
fn did_string(launcher: [u8; 32]) -> String {
    Address::new(Bytes32::from(launcher), "did:chia:".to_string())
        .encode()
        .unwrap()
}

#[test]
fn parses_a_well_formed_chia_did_and_extracts_the_launcher_id() {
    let launcher = [0x33u8; 32];
    let did_str = did_string(launcher);
    let did = parse_did_from_description(&format!("  {did_str}  ")).expect("parses");
    assert_eq!(did.as_str(), did_str);
    assert_eq!(did.launcher_id(), Bytes32::from(launcher));
    // Round-trips through the canonical constructor.
    assert_eq!(Did::parse(&did_str), Some(did));
}

#[test]
fn rejects_non_chia_did_descriptions() {
    assert!(parse_did_from_description("just a store").is_none());
    assert!(parse_did_from_description("did:chia:").is_none());
    // A valid bech32m address with the wrong prefix (an xch address) is not a DID.
    let xch = Address::new(Bytes32::from([0x44u8; 32]), "xch".to_string())
        .encode()
        .unwrap();
    assert!(parse_did_from_description(&xch).is_none());
}

// ---------- bidirectional-pairing predicate ----------

const SINGLETON_COIN_ID: [u8; 32] = [0xAA; 32];

fn singleton() -> IdentitySingleton {
    IdentitySingleton {
        did: Did::parse(&did_string([0x22; 32])).unwrap(),
        lineage: SingletonLineage::single(Bytes32::from(SINGLETON_COIN_ID)),
    }
}

/// A store launcher coin whose parent is `parent` (the authority channel).
fn launcher_coin(parent: [u8; 32]) -> Coin {
    Coin::new(Bytes32::from(parent), Bytes32::from([0x01; 32]), 1)
}

#[test]
fn both_links_present_is_authoritative() {
    let store = StoreRecord {
        description: did_string([0x22; 32]), // matches the singleton DID
        launcher_coin: launcher_coin(SINGLETON_COIN_ID), // launched from the singleton
    };
    assert!(is_authoritative_profile(&store, &singleton()));
    assert_eq!(store.launcher_id(), store.launcher_coin.coin_id());
}

#[test]
fn description_only_is_rejected() {
    // Discovery matches, but the launcher was NOT launched from the DID (spoof).
    let store = StoreRecord {
        description: did_string([0x22; 32]),
        launcher_coin: launcher_coin([0xBB; 32]), // wrong parent
    };
    let outcome = evaluate_pairing(&store, &singleton());
    assert!(outcome.discovery_matches);
    assert!(!outcome.authority_matches);
    assert!(!outcome.is_authoritative());
}

#[test]
fn lineage_only_is_rejected() {
    // Authority matches, but the description names a different DID.
    let store = StoreRecord {
        description: did_string([0x99; 32]), // a different DID
        launcher_coin: launcher_coin(SINGLETON_COIN_ID),
    };
    let outcome = evaluate_pairing(&store, &singleton());
    assert!(!outcome.discovery_matches);
    assert!(outcome.authority_matches);
    assert!(!outcome.is_authoritative());
}

// ---------- leaf-hash slot-key binding (B4 domain separation) ----------

#[test]
fn leaf_digest_binds_the_slot_key() {
    use dig_identity::hash::{hash_leaf_value, sha256, LEAF_DOMAIN};
    let encoded = Value::Utf8("Ada".into()).encode();

    // KAT: leaf_digest = sha256(0x01 ‖ slot_key ‖ encoded_value).
    let key_a = standard::DISPLAY_NAME.key();
    let mut preimage = vec![LEAF_DOMAIN];
    preimage.extend_from_slice(&key_a);
    preimage.extend_from_slice(&encoded);
    assert_eq!(hash_leaf_value(&key_a, &encoded), sha256(&preimage));

    // The SAME encoded value at a DIFFERENT slot yields a DIFFERENT leaf digest — the binding.
    let key_b = standard::BIO.key();
    assert_ne!(
        hash_leaf_value(&key_a, &encoded),
        hash_leaf_value(&key_b, &encoded)
    );

    // An absent (empty) value hashes to zero regardless of the slot key.
    assert_eq!(hash_leaf_value(&key_a, &[]), [0u8; 32]);
    assert_eq!(hash_leaf_value(&key_b, &[]), [0u8; 32]);
}

// ---------- xch_address standard field (slot 0x0008) ----------

fn xch_address_string(payload: [u8; 32]) -> String {
    Address::new(Bytes32::from(payload), "xch".to_string())
        .encode()
        .unwrap()
}

#[test]
fn xch_address_accessor_accepts_a_canonical_mainnet_address() {
    let addr = xch_address_string([0x55; 32]);
    let mut profile = Profile::with_schema_v2();
    profile.set(standard::XCH_ADDRESS, Value::Utf8(addr.clone()));
    assert_eq!(profile.xch_address(), Some(addr.as_str()));
    // Provable against the root like any other field.
    let tree = profile.build_tree().unwrap();
    let proof = tree.prove_membership(standard::XCH_ADDRESS).unwrap();
    assert!(verify_membership(
        &tree.root(),
        standard::XCH_ADDRESS,
        &Value::Utf8(addr),
        &proof
    )
    .unwrap());
}

#[test]
fn xch_address_accessor_rejects_non_canonical_values() {
    use dig_identity::xch::{is_valid_xch_address, parse_xch_address};
    // Wrong HRP (a testnet txch address), a DID string, and garbage are all rejected.
    let txch = Address::new(Bytes32::from([0x66; 32]), "txch".to_string())
        .encode()
        .unwrap();
    assert!(!is_valid_xch_address(&txch));
    assert!(!is_valid_xch_address(&did_string([0x77; 32])));
    assert!(!is_valid_xch_address("not-an-address"));
    // A canonical address round-trips through the parser (trimmed).
    let addr = xch_address_string([0x55; 32]);
    assert_eq!(parse_xch_address(&format!("  {addr} ")), Some(addr.clone()));

    // The accessor returns None for a present-but-invalid slot value.
    let mut profile = Profile::new();
    profile.set(standard::XCH_ADDRESS, Value::Utf8(txch));
    assert_eq!(profile.xch_address(), None);
    // ...and None when the slot is absent.
    assert_eq!(Profile::new().xch_address(), None);
}

// ---------- store_belongs_to_did + StoreOwnershipProof ----------

#[test]
fn store_belongs_to_did_and_ownership_proof_require_both_links() {
    use dig_identity::{store_belongs_to_did, StoreOwnershipProof};
    let authoritative = StoreRecord {
        description: did_string([0x22; 32]),
        launcher_coin: launcher_coin(SINGLETON_COIN_ID),
    };
    assert!(store_belongs_to_did(&authoritative, &singleton()));
    let proof = StoreOwnershipProof::new(singleton(), authoritative);
    assert!(proof.verify());
    assert!(proof.outcome().is_authoritative());

    // Description-only (wrong lineage) and lineage-only (wrong description) both fail.
    let desc_only = StoreRecord {
        description: did_string([0x22; 32]),
        launcher_coin: launcher_coin([0xBB; 32]),
    };
    assert!(!store_belongs_to_did(&desc_only, &singleton()));
    assert!(!StoreOwnershipProof::new(singleton(), desc_only).verify());

    let lineage_only = StoreRecord {
        description: did_string([0x99; 32]),
        launcher_coin: launcher_coin(SINGLETON_COIN_ID),
    };
    assert!(!StoreOwnershipProof::new(singleton(), lineage_only).verify());
}

#[test]
fn store_ownership_proof_is_relative_to_a_trusted_coin_id_not_trustless() {
    // Pins the DOCUMENTED trust boundary of `StoreOwnershipProof` (NOT a bug): `verify()` re-runs the
    // pairing predicate, but `singleton.lineage` is a caller-supplied field the predicate does NOT
    // authenticate. So an attacker can forge a proof that passes the predicate yet does NOT prove
    // on-chain ownership — which is exactly why WU3 MUST resolve `lineage` on-chain (as the DID's
    // authentic singleton lineage) before any consumer trusts this bundle.
    //
    use dig_identity::StoreOwnershipProof;
    // The attack: the attacker launches store S from their OWN coin `C_att`, describes S as the
    // VICTIM's DID, and supplies a `lineage` containing `C_att` (their own coin, never resolved against
    // the victim DID's real singleton). Discovery ✓ (description names the victim DID) and authority ✓
    // (`launcher_coin.parent == C_att ∈ lineage`) → the predicate accepts.
    let victim_did = Did::parse(&did_string([0x22; 32])).unwrap();
    let attacker_coin_id = Bytes32::from([0xEE; 32]); // C_att — the attacker's own coin, NOT resolved

    let forged = StoreOwnershipProof::new(
        IdentitySingleton {
            did: victim_did,
            lineage: SingletonLineage::single(attacker_coin_id),
        },
        StoreRecord {
            description: did_string([0x22; 32]), // claims to be the victim DID's profile
            launcher_coin: launcher_coin([0xEE; 32]), // launched from C_att, so parent == coin_id
        },
    );

    // The predicate accepts — this is the trap. It means only "these records satisfy the predicate",
    // NOT "S is chain-authenticated as the victim DID's profile". Soundness requires `coin_id` to be
    // externally resolved on-chain (WU3); the predicate alone is NOT trustless.
    assert!(forged.verify());
    assert!(forged.outcome().is_authoritative());
}

// ---------- composed verify_profile_field_for_did ----------

/// An authoritative store for the test `singleton()` plus a profile committed to its root.
fn authoritative_profile() -> (StoreRecord, Profile) {
    let store = StoreRecord {
        description: did_string([0x22; 32]),
        launcher_coin: launcher_coin(SINGLETON_COIN_ID),
    };
    let mut profile = Profile::with_schema_v2();
    profile.set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()));
    (store, profile)
}

#[test]
fn composed_verify_accepts_a_genuine_field() {
    use dig_identity::verify_profile_field_for_did;
    let (store, profile) = authoritative_profile();
    let tree = profile.build_tree().unwrap();
    let root = tree.root();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();

    assert_eq!(
        verify_profile_field_for_did(
            &singleton(),
            &store,
            &root,
            standard::DISPLAY_NAME,
            &Value::Utf8("Ada".into()),
            &proof,
        ),
        Ok(true)
    );
}

#[test]
fn composed_verify_errors_when_store_is_not_authoritative() {
    use dig_identity::{verify_profile_field_for_did, Error};
    let (_, profile) = authoritative_profile();
    let tree = profile.build_tree().unwrap();
    let root = tree.root();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
    // Discovery matches but lineage does not — a spoofed store.
    let spoof = StoreRecord {
        description: did_string([0x22; 32]),
        launcher_coin: launcher_coin([0xBB; 32]),
    };
    assert_eq!(
        verify_profile_field_for_did(
            &singleton(),
            &spoof,
            &root,
            standard::DISPLAY_NAME,
            &Value::Utf8("Ada".into()),
            &proof,
        ),
        Err(Error::NotAuthoritativeProfile)
    );
}

#[test]
fn composed_verify_errors_on_a_tampered_value() {
    use dig_identity::{verify_profile_field_for_did, Error};
    let (store, profile) = authoritative_profile();
    let tree = profile.build_tree().unwrap();
    let root = tree.root();
    let proof = tree.prove_membership(standard::DISPLAY_NAME).unwrap();
    assert_eq!(
        verify_profile_field_for_did(
            &singleton(),
            &store,
            &root,
            standard::DISPLAY_NAME,
            &Value::Utf8("Mallory".into()), // wrong value
            &proof,
        ),
        Err(Error::FieldProofRejected)
    );
}

#[test]
fn composed_absent_verify_accepts_and_rejects() {
    use dig_identity::{verify_profile_field_absent_for_did, Error};
    let (store, profile) = authoritative_profile();
    let tree = profile.build_tree().unwrap();
    let root = tree.root();

    // Accepts a genuine absence.
    let absent = tree.prove_non_membership(standard::PEER_ID).unwrap();
    assert_eq!(
        verify_profile_field_absent_for_did(
            &singleton(),
            &store,
            &root,
            standard::PEER_ID,
            &absent,
        ),
        Ok(true)
    );

    // Rejects when the store is not authoritative.
    let spoof = StoreRecord {
        description: did_string([0x99; 32]), // wrong DID
        launcher_coin: launcher_coin(SINGLETON_COIN_ID),
    };
    assert_eq!(
        verify_profile_field_absent_for_did(
            &singleton(),
            &spoof,
            &root,
            standard::PEER_ID,
            &absent,
        ),
        Err(Error::NotAuthoritativeProfile)
    );
}
