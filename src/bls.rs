//! The BLS12-381 identity key model (SPEC §6a) — derivation + the sign/seal primitives.
//!
//! The DIG identity key is a SINGLE Chia-compatible BLS12-381 keypair (minimal-pubkey-size): a
//! 48-byte compressed **G1** public key (profile slot `0x0010`), a scalar private key, and a 96-byte
//! compressed **G2** signature. ONE keypair serves BOTH identity uses:
//!
//! - **sign** — BLS G2 via the Chia AugScheme ([`sign_message`] / [`verify_signature`]);
//! - **seal DH** — G1 ECDH `dh(sk, pk) = sk·pk` ([`g1_dh`]), the DH primitive of dig-message's
//!   DHKEM-over-G1 seal (the KDF/AEAD composition lives in dig-message, not here).
//!
//! The same-key safety argument (distinct groups + distinct domains, non-custodial key path, and the
//! well-defined self-DH) is recorded in SPEC §6a.4; it is cited, not re-derived, here.
//!
//! Derivation is wallet-controlled and NON-custodial: the identity key is derived from the wallet
//! master via EIP-2333 at the FIXED path [`IDENTITY_DERIVATION_PATH`] = `m/12381'/8444'/9'/0'`, which
//! is DISTINCT from Chia's wallet coin path (`.../2'/n`). That distinctness is load-bearing — the
//! identity key secures NO coins, so a confused-deputy signature on it authorizes nothing (§6a.4).
//!
//! Derivation, signing, and verification delegate to the vetted `chia-bls` crate; the ONE operation
//! it does not expose — raw G1 scalar-multiplication for the ECDH, plus the G1 subgroup/non-identity
//! check — uses the low-level `blst` backend. BLS and the curve arithmetic are NEVER hand-rolled.

use blst::{
    blst_p1, blst_p1_affine, blst_p1_affine_in_g1, blst_p1_affine_is_inf, blst_p1_compress,
    blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress, blst_scalar,
    blst_scalar_from_bendian, BLST_ERROR,
};
use chia_bls::{sign as aug_sign, verify as aug_verify};
pub use chia_bls::{PublicKey, SecretKey, Signature};

/// The canonical dig-identity hardened derivation path `m/12381'/8444'/9'/0'` (SPEC §6a.1).
///
/// Every index is hardened. `12381` = the BLS12-381 purpose, `8444` = the Chia coin type, `9` = the
/// dig-identity application index (DISTINCT from Chia's wallet key index `2` — this key secures no
/// coins), `0` = the identity key index — i.e. profile index `0`, the default profile
/// ([`derive_identity_sk_at`] generalizes this last hardened component to any profile).
pub const IDENTITY_DERIVATION_PATH: [u32; 4] = [12381, 8444, 9, 0];

/// The fixed prefix of the dig-identity hardened path — the purpose, coin type, and application index
/// `m/12381'/8444'/9'` shared by EVERY profile. Only the final hardened component (the profile index)
/// varies per profile ([`derive_identity_sk_at`]); it is kept PRIVATE so consumers derive through the
/// functions and never re-assemble the raw path (SPEC §6a.1, dig_ecosystem §4.1).
const IDENTITY_PATH_PREFIX: [u32; 3] = [12381, 8444, 9];

/// The canonical compressed encoding of the G1 identity element (point at infinity): the compression
/// and infinity flag bits in the first byte, all coordinate bytes zero (ZCash/Chia BLS12-381
/// serialization). Rejected everywhere a real key is expected.
const G1_INFINITY: [u8; 48] = {
    let mut bytes = [0u8; 48];
    bytes[0] = 0xc0;
    bytes
};

/// Derives the EIP-2333 master secret key from a wallet seed (`chia_bls::SecretKey::from_seed`).
///
/// This is the ROOT of the wallet's key tree; [`derive_identity_sk`] applies the dig-identity path to
/// it. Pass a real wallet seed (e.g. the BIP-39 mnemonic seed) exactly once — never re-run this on an
/// already-derived scalar (that would treat a derived key as fresh entropy).
pub fn master_secret_key_from_seed(seed: &[u8]) -> SecretKey {
    SecretKey::from_seed(seed)
}

/// Derives the dig-identity secret key from a wallet master key at [`IDENTITY_DERIVATION_PATH`].
///
/// Applies the four hardened EIP-2333 steps `m/12381'/8444'/9'/0'` (SPEC §6a.1). The result is the
/// identity keypair's private scalar; its [`public_key_bytes`] is the 48-byte G1 key published in
/// slot `0x0010`.
///
/// This is the default profile (`profile_ix = 0`): it is byte-identical to
/// [`derive_identity_sk_at(master, 0)`](derive_identity_sk_at) and delegates to it.
pub fn derive_identity_sk(master: &SecretKey) -> SecretKey {
    derive_identity_sk_at(master, 0)
}

/// Derives the dig-identity secret key for a specific PROFILE from a wallet master key, at the
/// per-profile hardened path `m/12381'/8444'/9'/{profile_ix}'` (SPEC §6a.1).
///
/// The purpose (`12381'`), coin type (`8444'`), and application index (`9'`) are the shared
/// [`IDENTITY_PATH_PREFIX`]; the caller-supplied `profile_ix` is the FINAL hardened component, so
/// each profile gets an independent, non-custodial identity keypair off the same wallet master. A
/// wallet with N profiles derives N distinct identity keys — one per `profile_ix` — all off the same
/// seed, none securing any coins (the `9'` application index is DISTINCT from Chia's wallet coin path
/// `2'`, §6a.4 point 2).
///
/// `profile_ix = 0` is the default profile and is byte-identical to [`derive_identity_sk`] /
/// [`IDENTITY_DERIVATION_PATH`] — the historical fixed path is exactly profile index 0. This is an
/// additive generalization (dig_ecosystem §5.1): existing callers are unaffected.
pub fn derive_identity_sk_at(master: &SecretKey, profile_ix: u32) -> SecretKey {
    let prefixed = IDENTITY_PATH_PREFIX
        .iter()
        .fold(master.clone(), |sk, &index| sk.derive_hardened(index));
    prefixed.derive_hardened(profile_ix)
}

/// The 48-byte compressed BLS12-381 G1 public key for a secret key.
pub fn public_key_bytes(sk: &SecretKey) -> [u8; 48] {
    sk.public_key().to_bytes()
}

/// Validates that `pk` is a canonical, non-identity G1 point in the prime-order `r`-subgroup (§6a.3).
///
/// Returns `true` only when `pk` deserializes as a compressed point ON the curve, lies in the
/// `r`-subgroup (`blst` `in_g1`), and is NOT the identity/infinity point. A point failing any check
/// (malformed, off-curve, small-order, or identity) returns `false`. This is the mandatory gate
/// before any DH — it blocks small-subgroup / invalid-curve key-recovery attacks.
pub fn g1_subgroup_check(pk: &[u8; 48]) -> bool {
    if pk == &G1_INFINITY {
        return false;
    }
    // SAFETY: `blst` FFI over fixed-size, initialized stack buffers; no aliasing, no lifetimes escape.
    unsafe {
        let mut affine = blst_p1_affine::default();
        if blst_p1_uncompress(&mut affine, pk.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return false;
        }
        if blst_p1_affine_is_inf(&affine) {
            return false;
        }
        blst_p1_affine_in_g1(&affine)
    }
}

/// The G1 ECDH primitive `dh(sk, peer_g1) = sk · peer_g1`, returning the 48-byte compressed result
/// point (SPEC §6a.2), or `None` when `peer_g1` fails the §6a.3 subgroup / non-identity check.
///
/// This is the DH used by both the sender encapsulation and the recipient decapsulation of
/// dig-message's DHKEM-over-G1 seal. The subgroup validation of `peer_g1` is applied here, so a
/// caller can never perform a DH against an invalid or small-subgroup point.
pub fn g1_dh(sk: &SecretKey, peer_g1: &[u8; 48]) -> Option<[u8; 48]> {
    if !g1_subgroup_check(peer_g1) {
        return None;
    }
    let scalar_bytes = sk.to_bytes();
    // SAFETY: `blst` FFI over fixed-size, initialized stack buffers checked above; the scalar comes
    // from a valid secret key and the point passed the subgroup check.
    unsafe {
        let mut affine = blst_p1_affine::default();
        if blst_p1_uncompress(&mut affine, peer_g1.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return None;
        }
        let mut point = blst_p1::default();
        blst_p1_from_affine(&mut point, &affine);

        let mut scalar = blst_scalar::default();
        blst_scalar_from_bendian(&mut scalar, scalar_bytes.as_ptr());

        let mut product = blst_p1::default();
        blst_p1_mult(&mut product, &point, scalar.b.as_ptr(), 255);

        // A real secret key (scalar in 1..r) times a prime-order-subgroup point is never the identity;
        // reject defensively so a degenerate shared secret can never escape.
        let mut product_affine = blst_p1_affine::default();
        blst_p1_to_affine(&mut product_affine, &product);
        if blst_p1_affine_is_inf(&product_affine) {
            return None;
        }

        let mut compressed = [0u8; 48];
        blst_p1_compress(compressed.as_mut_ptr(), &product);
        Some(compressed)
    }
}

/// Signs `msg` with the identity key under the Chia AugScheme (BLS G2), returning the 96-byte
/// compressed signature (SPEC §6a.2).
///
/// dig-message signs `SIG_DOMAIN || transcript` through this helper ONLY — NEVER through any wallet
/// spend-signing code path (§6a.4 point 2). AugScheme prepends the public key and hashes to G2 with
/// the Chia DST, binding the signer's key.
pub fn sign_message(sk: &SecretKey, msg: &[u8]) -> [u8; 96] {
    aug_sign(sk, msg).to_bytes()
}

/// Verifies a 96-byte AugScheme signature against a 48-byte G1 identity key and `msg` (SPEC §6a.2).
///
/// Returns `false` on any malformed key/signature bytes or a non-verifying signature (fail-closed).
pub fn verify_signature(pk: &[u8; 48], msg: &[u8], sig: &[u8; 96]) -> bool {
    let (Ok(pk), Ok(sig)) = (PublicKey::from_bytes(pk), Signature::from_bytes(sig)) else {
        return false;
    };
    aug_verify(&sig, &pk, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A reproducible, cross-impl test seed derived from a label (never a hard-coded literal, so a
    /// second implementation reproduces the same vector from the same label, and CodeQL does not flag
    /// a hard-coded cryptographic value).
    fn seed_from_label(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn identity_sk(label: &str) -> SecretKey {
        derive_identity_sk(&master_secret_key_from_seed(&seed_from_label(label)))
    }

    /// The derivation KAT: `derive_identity_sk` reproduces the manual EIP-2333 hardened chain at
    /// `m/12381'/8444'/9'/0'` via `chia-bls` directly — proving the path wiring byte-agrees with
    /// chia-wallet-sdk's derivation (which uses the same `chia-bls` primitives).
    #[test]
    fn derivation_matches_the_manual_chia_bls_chain() {
        let seed = seed_from_label("dig-identity/kat/derivation/v2");
        let ours = derive_identity_sk(&master_secret_key_from_seed(&seed));

        let mut reference = SecretKey::from_seed(&seed);
        for index in [12381u32, 8444, 9, 0] {
            reference = reference.derive_hardened(index);
        }

        assert_eq!(ours.to_bytes(), reference.to_bytes());
        assert_eq!(public_key_bytes(&ours), reference.public_key().to_bytes());
        // The published key is a valid, non-identity G1 subgroup point.
        assert!(g1_subgroup_check(&public_key_bytes(&ours)));
    }

    #[test]
    fn derivation_is_deterministic_and_path_is_canonical() {
        assert_eq!(IDENTITY_DERIVATION_PATH, [12381, 8444, 9, 0]);
        let a = identity_sk("dig-identity/kat/deterministic");
        let b = identity_sk("dig-identity/kat/deterministic");
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    /// Byte-identity invariant (dig_ecosystem §5.1): `derive_identity_sk` is exactly profile 0, so the
    /// generalized `derive_identity_sk_at(master, 0)` reproduces the historical fixed-path key to the
    /// byte — both the private scalar and the published G1 public key.
    #[test]
    fn profile_zero_is_byte_identical_to_the_fixed_path() {
        let master = master_secret_key_from_seed(&seed_from_label("dig-identity/kat/profile-zero"));
        let fixed = derive_identity_sk(&master);
        let profile_zero = derive_identity_sk_at(&master, 0);
        assert_eq!(profile_zero.to_bytes(), fixed.to_bytes());
        assert_eq!(public_key_bytes(&profile_zero), public_key_bytes(&fixed));
    }

    /// Per-profile derivation is deterministic and each profile index yields a DISTINCT key — profile
    /// 1 differs from profile 0, and the generalized path matches the manual EIP-2333 chain at
    /// `m/12381'/8444'/9'/{profile_ix}'`.
    #[test]
    fn per_profile_derivation_is_distinct_and_matches_manual_chain() {
        let master = master_secret_key_from_seed(&seed_from_label("dig-identity/kat/per-profile"));

        let profile_zero = derive_identity_sk_at(&master, 0);
        let profile_one = derive_identity_sk_at(&master, 1);
        let profile_two = derive_identity_sk_at(&master, 2);
        assert_ne!(profile_one.to_bytes(), profile_zero.to_bytes());
        assert_ne!(profile_two.to_bytes(), profile_one.to_bytes());

        // Deterministic: same master + index reproduces the same key.
        assert_eq!(
            derive_identity_sk_at(&master, 1).to_bytes(),
            profile_one.to_bytes()
        );

        // Matches the manual hardened chain m/12381'/8444'/9'/1'.
        let mut reference = master.clone();
        for index in [12381u32, 8444, 9, 1] {
            reference = reference.derive_hardened(index);
        }
        assert_eq!(profile_one.to_bytes(), reference.to_bytes());
    }

    /// The load-bearing non-custodial property (§6a.4 point 2): the identity key at purpose `9'`
    /// differs from the wallet coin key at purpose `2'`, so the identity key secures no coins.
    #[test]
    fn identity_path_differs_from_the_wallet_coin_path() {
        let seed = seed_from_label("dig-identity/kat/non-custodial");
        let master = master_secret_key_from_seed(&seed);
        let identity = derive_identity_sk(&master);

        // The Chia wallet coin path m/12381'/8444'/2'/0'.
        let mut wallet = master.clone();
        for index in [12381u32, 8444, 2, 0] {
            wallet = wallet.derive_hardened(index);
        }
        assert_ne!(public_key_bytes(&identity), public_key_bytes(&wallet));
    }

    #[test]
    fn g1_ecdh_round_trip_agrees_on_both_sides() {
        let a = identity_sk("dig-identity/kat/ecdh/a");
        let b = identity_sk("dig-identity/kat/ecdh/b");
        let a_pk = public_key_bytes(&a);
        let b_pk = public_key_bytes(&b);

        let from_a = g1_dh(&a, &b_pk).expect("valid peer point");
        let from_b = g1_dh(&b, &a_pk).expect("valid peer point");
        assert_eq!(from_a, from_b);
    }

    /// The self-addressed case (§6a.4 point 3): `dh(sk, own_pk)` is valid and non-degenerate.
    #[test]
    fn self_dh_is_valid_and_non_degenerate() {
        let sk = identity_sk("dig-identity/kat/self-dh");
        let pk = public_key_bytes(&sk);
        let shared = g1_dh(&sk, &pk).expect("self-DH is well-defined");
        assert!(g1_subgroup_check(&shared)); // a valid, non-identity result point
        assert_ne!(shared, pk); // sk²·G1 is not the public key sk·G1
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = identity_sk("dig-identity/kat/sign");
        let pk = public_key_bytes(&sk);
        let msg = b"DIGNET-MSG:dig-message/v1 transcript bytes";

        let sig = sign_message(&sk, msg);
        assert!(verify_signature(&pk, msg, &sig));
        // A different message does not verify.
        assert!(!verify_signature(&pk, b"other", &sig));
        // A different key does not verify.
        let other_pk = public_key_bytes(&identity_sk("dig-identity/kat/sign-other"));
        assert!(!verify_signature(&other_pk, msg, &sig));
    }

    /// Sign/DH domain separation (§6a.4 point 1): a G2 signature (96 bytes) and a G1 DH value
    /// (48 bytes) live in different groups and cannot serve as each other. Neither is an oracle for
    /// the other.
    #[test]
    fn sign_and_dh_are_domain_separated() {
        let sk = identity_sk("dig-identity/kat/domain-sep");
        let pk = public_key_bytes(&sk);
        let msg = b"message";

        let sig = sign_message(&sk, msg); // [u8; 96], a G2 point
        let dh = g1_dh(&sk, &pk).expect("valid"); // [u8; 48], a G1 point
        assert_eq!(sig.len(), 96);
        assert_eq!(dh.len(), 48);

        // A DH result (a G1 point) is not a usable G2 signature: padded to 96 bytes it never verifies.
        let mut forged_sig = [0u8; 96];
        forged_sig[..48].copy_from_slice(&dh);
        assert!(!verify_signature(&pk, msg, &forged_sig));
    }

    #[test]
    fn subgroup_check_rejects_identity_and_malformed_points() {
        // The identity / infinity point is rejected.
        assert!(!g1_subgroup_check(&G1_INFINITY));
        // A malformed (non-canonical / off-curve) compressed point is rejected.
        assert!(!g1_subgroup_check(&[0xffu8; 48]));

        // g1_dh refuses to DH against a rejected point.
        let sk = identity_sk("dig-identity/kat/subgroup");
        assert_eq!(g1_dh(&sk, &G1_INFINITY), None);
        assert_eq!(g1_dh(&sk, &[0xffu8; 48]), None);

        // A genuine derived key passes.
        assert!(g1_subgroup_check(&public_key_bytes(&sk)));
    }
}
