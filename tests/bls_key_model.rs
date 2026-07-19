//! Cross-implementation golden KAT for the BLS12-381 G1 identity key model (SPEC §6a).
//!
//! Exercised through the crate's PUBLIC API only, so a second (wasm/JS) implementation can reproduce
//! the same vectors. The fixed seed is derived from a documented label (never a hard-coded literal),
//! so the vector is reproducible cross-impl and carries no hard-coded cryptographic secret. The
//! golden G1 public key is the expected OUTPUT (a public key vector), not a secret.

use dig_identity::{
    derive_identity_sk, g1_dh, g1_subgroup_check, master_secret_key_from_seed, public_key_bytes,
    sign_message, verify_signature, IDENTITY_DERIVATION_PATH,
};
use sha2::{Digest, Sha256};

/// The documented cross-impl KAT seed = `sha256("dig-identity/kat/golden/v2")`.
fn golden_seed() -> [u8; 32] {
    Sha256::digest(b"dig-identity/kat/golden/v2").into()
}

/// The golden 48-byte compressed BLS12-381 G1 identity public key derived at
/// `m/12381'/8444'/9'/0'` (`IDENTITY_DERIVATION_PATH`) from [`golden_seed`]. A conforming second
/// implementation MUST reproduce these exact bytes.
const GOLDEN_G1_PUBLIC_KEY: [u8; 48] = [
    163, 85, 55, 132, 105, 100, 163, 191, 241, 195, 141, 129, 242, 26, 120, 233, 4, 10, 138, 180,
    116, 70, 134, 120, 72, 5, 12, 144, 75, 77, 89, 84, 173, 218, 184, 70, 73, 218, 18, 117, 197,
    131, 241, 100, 198, 200, 126, 31,
];

/// The derivation KAT: the documented seed derives to the golden G1 public key at the canonical
/// dig-identity path — the cross-impl anchor for wasm/JS parity.
#[test]
fn derivation_reproduces_the_golden_g1_public_key() {
    assert_eq!(IDENTITY_DERIVATION_PATH, [12381, 8444, 9, 0]);
    let sk = derive_identity_sk(&master_secret_key_from_seed(&golden_seed()));
    assert_eq!(public_key_bytes(&sk), GOLDEN_G1_PUBLIC_KEY);
    assert!(g1_subgroup_check(&GOLDEN_G1_PUBLIC_KEY));
}

/// The G1-ECDH round-trip agrees sender-side and recipient-side (SPEC §6a.6 (b)).
#[test]
fn g1_ecdh_round_trip_agrees_via_public_api() {
    let seed_a: [u8; 32] = Sha256::digest(b"dig-identity/kat/pub/a").into();
    let seed_b: [u8; 32] = Sha256::digest(b"dig-identity/kat/pub/b").into();
    let a = derive_identity_sk(&master_secret_key_from_seed(&seed_a));
    let b = derive_identity_sk(&master_secret_key_from_seed(&seed_b));

    let from_a = g1_dh(&a, &public_key_bytes(&b)).expect("valid peer point");
    let from_b = g1_dh(&b, &public_key_bytes(&a)).expect("valid peer point");
    assert_eq!(from_a, from_b);
}

/// Sign/verify round-trips and a subgroup-invalid point is rejected — the seal/sign primitives are
/// reachable and fail-closed through the public API.
#[test]
fn sign_verify_and_subgroup_reject_via_public_api() {
    let sk = derive_identity_sk(&master_secret_key_from_seed(&golden_seed()));
    let pk = public_key_bytes(&sk);
    let msg = b"transcript";

    let sig = sign_message(&sk, msg);
    assert!(verify_signature(&pk, msg, &sig));

    // A malformed / non-subgroup point is rejected, and g1_dh refuses it.
    let bogus = [0xffu8; 48];
    assert!(!g1_subgroup_check(&bogus));
    assert_eq!(g1_dh(&sk, &bogus), None);
}
