# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-07-19

### ⚠ BREAKING CHANGES
- **Identity key model reset to BLS-G1-only (schema v2).** Slot `0x0010` is re-encoded from a 32-byte
  Ed25519 signing key to a 48-byte compressed BLS12-381 **G1** identity key, and slot `0x0011`
  (X25519 encryption key) is RETIRED. The single BLS G1 key now serves BOTH signing (BLS G2,
  AugSchemeMPL) and sealing (G1 ECDH). No Ed25519, no X25519. This is a sanctioned one-time
  pre-release schema reset — the crate is pre-1.0 and pre-release with zero on-chain profiles, so no
  published bytes are broken (SPEC §2.4). `SCHEMA_VERSION_V2 = 2`; there is no v1 read path.
- **API:** `resolve_signing_key(did) -> [u8; 32]` becomes `resolve_bls_public_key(did) -> [u8; 48]`;
  `ResolveError::NoSigningKey` becomes `ResolveError::NoIdentityKey`; `DidKeys.signing_public_key` +
  `DidKeys.encryption_public_key` become `DidKeys.bls_g1_public_key: Option<[u8; 48]>`;
  `Profile::with_schema_v1` becomes `Profile::with_schema_v2`; `standard::SIGNING_PUBLIC_KEY` +
  `standard::ENCRYPTION_PUBLIC_KEY` become `standard::BLS_G1_PUBLIC_KEY`; `SCHEMA_VERSION_V1` becomes
  `SCHEMA_VERSION_V2`.

### Features
- **dig-identity:** BLS12-381 G1 identity key model (§6a), behind the default-on `bls` feature:
  `derive_identity_sk` at the canonical path `m/12381'/8444'/9'/0'` (distinct from the wallet coin
  path, so the identity key secures no coins), `g1_dh` (the seal ECDH `sk·pk`, subgroup-checked),
  `g1_subgroup_check`, `sign_message`/`verify_signature` (AugSchemeMPL), `public_key_bytes`,
  `master_secret_key_from_seed`, and `IDENTITY_DERIVATION_PATH`. Delegates to `chia-bls` + `blst`;
  never hand-rolls BLS. Unblocks the dig-message WU2 e2e seal (#1160). (#1169)

BREAKING CHANGE: the dig-identity key model changed from Ed25519(0x0010)+X25519(0x0011) to a single
BLS12-381 G1 key (0x0010) doing both G2-sign and G1-ECDH-seal; see the API changes above.

## [0.3.0] - 2026-07-19

### Features
- **dig-identity:** WU3 on-chain DID chain-resolution (resolve_did_keys / resolve_signing_key) (#3)

## [0.2.0] - 2026-07-18

### Features
- **dig-identity:** Add IdentityProfile primitive (DID + chip35 store + profile SMT) (#777) (#2)

## [0.1.0] - 2026-07-17

### Features
- **dig-identity:** WU1 canonical DID-profile format crate (#1)


