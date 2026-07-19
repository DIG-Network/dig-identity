# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.3.0] - 2026-07-18

### Features
- **dig-identity:** WU3 on-chain DID chain-resolution over a caller-supplied `ChainSource` trait seam — `resolve_identity_profile` / `resolve::resolve_did_keys` / `resolve_signing_key` derive the identity singleton coin and profile root from the DID (never a producer-supplied `coin_id`), fail closed on not-found / ambiguity / stale-or-tampered root, and defeat the authority-laundering spoof. The `DidSigningKeyResolver` seam #1007 consumes. No network dependency added — the crate still builds for wasm/no-network targets. (#778) (#3)

## [0.2.0] - 2026-07-18

### Features
- **dig-identity:** Add IdentityProfile primitive (DID + chip35 store + profile SMT) (#777) (#2)

## [0.1.0] - 2026-07-17

### Features
- **dig-identity:** WU1 canonical DID-profile format crate (#1)


