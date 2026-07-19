# dig-identity

The canonical DIG decentralized-identity **profile format**: a Chia identity anchor (a `did:chia:`
singleton in v1) paired with a chip35 DataLayer store that holds the anchor's profile as a standard,
extendable **sparse merkle tree** of slots. Each identity field lives at a fixed slot; any field can
be proved — or proved absent — against a single 32-byte root.

The format core holds no network dependency. On-chain DID resolution (WU3) is a caller-supplied
`ChainSource` **trait** seam, and the BLS identity key model (§6a) is behind the default-on `bls`
feature — so the pure format layer still builds for wasm / no-network targets with
`default-features = false`. The DID→dig-store minting driver (WU2) is a follow-on. See
[`SPEC.md`](./SPEC.md) for the normative byte-level contract.

**Identity key model (v2, BLS-G1-only):** the identity key is a SINGLE Chia-compatible BLS12-381 G1
key (slot `0x0010`, 48-byte compressed pubkey) that does BOTH signing (BLS G2, AugSchemeMPL) and
sealing (G1 ECDH). There is no Ed25519 and no X25519 — the v1 slot `0x0011` (X25519) is retired. This
is the key model dig-message's e2e seal consumes.

## What it provides

- Deterministic slot-key derivation and the v2 standard slot map (+ reserved ranges, additive-only).
- A hand-rolled `tag ‖ len ‖ bytes` value encoding that Rust/JS/wasm reproduce byte-for-byte.
- A sha256 sparse merkle tree (Nervos `sparse-merkle-tree`) with membership + non-membership proofs.
- Root-only proof verification ("this DID's field == X" / "this field is absent") from `(root, proof)`.
- `DID→keys` resolution (BLS G1 identity key / peer_id / key_epoch) — the dig-message / dig-node seam.
- The BLS identity key model (`bls`): derivation at `m/12381'/8444'/9'/0'`, `g1_dh` (seal ECDH),
  `sign_message`/`verify_signature` (BLS G2), and the mandatory `g1_subgroup_check`.
- The DID↔store bidirectional-pairing predicate (description discovery + launch-from-DID authority),
  which REJECTS description-only matches.
- The `IdentityProfile` primitive (v0.2.0) — the managed DID + store + profile-SMT object.

### The identity key — derive, sign, seal-DH

```rust
use dig_identity::{derive_identity_sk, master_secret_key_from_seed, public_key_bytes, g1_dh};

// Derive the identity key from the wallet master at the canonical dig-identity path (secures no coins).
let master = master_secret_key_from_seed(&wallet_seed);
let sk = derive_identity_sk(&master);
let my_g1 = public_key_bytes(&sk);          // publish in slot 0x0010

// Seal DH against a peer's resolved BLS G1 key (subgroup-checked internally; None if invalid).
let shared = g1_dh(&sk, &peer_g1).expect("valid peer point");
```

## Example

```rust
use dig_identity::{Profile, Value, slot::standard, proof};

let mut profile = Profile::with_schema_v2();
profile.set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()));

let tree = profile.build_tree()?;
let root = tree.root();

let membership = tree.prove_membership(standard::DISPLAY_NAME)?;
let claim = Value::Utf8("Ada".into());
assert!(proof::verify_membership(&root, standard::DISPLAY_NAME, &claim, &membership)?);
# Ok::<(), dig_identity::Error>(())
```

## The `IdentityProfile` primitive

`Profile` (above) is just the metadata slot-map. `IdentityProfile` is the **managed object** that
composes the three things a DIG identity is at rest into one lifecycle:

- the **DID identity singleton** (its anchor — a `did:chia:` DID plus the singleton coin id you
  resolved on-chain),
- the **paired chip35 DataLayer store** launched from that DID, and
- the **profile SMT** (`Profile`) it commits to, with the current committed root.

This is the object dig-chat / dig-email / dig-video-chat and dig-app profiles build on, instead of
re-assembling the triple by hand. It wraps `Profile` — it does not replace it. The pairing/proof
contract it enforces is normative in [`SPEC.md`](./SPEC.md) §8.1.

### Resolve a paired profile

`IdentityProfile::resolve` constructs the primitive **only** when the store genuinely belongs to the
DID — the store must name the DID in its description AND have been launched from the DID singleton.
A description-only or lineage-only (spoofed) store is rejected, so an `IdentityProfile` value can
only exist for a paired store.

```rust
use dig_identity::{IdentityProfile, Profile, Value, slot::standard};

// `singleton` (DID + on-chain-resolved coin id) and `store` (the paired chip35 store record) come
// from your chain resolver; `metadata` is the profile you read back from the store.
let identity = IdentityProfile::resolve(singleton, store, metadata)?;

assert!(identity.store_belongs_to_did());
let name = identity.display_name();          // read accessors delegate to the inner Profile
let keys = identity.keys();                  // signing / encryption / peer_id / key_epoch
let pay_to = identity.xch_address();         // the $DIG-payments seam, if published
# Ok::<(), dig_identity::Error>(())
```

> Soundness is **relative to** a `coin_id` you resolved on-chain yourself. `resolve` verifies the
> pairing predicate over the records you give it; it does not authenticate the coin id for you. Never
> pass a coin id supplied by an untrusted producer.

### Resolve a DID on-chain (WU3)

When you have a chain backend, `resolve_identity_profile` does the authentication for you: from just a
`did:chia:` string it walks the DID singleton to its authentic current coin, finds the paired store,
binds the profile body to the store's current on-chain root, and fails closed on anything ambiguous or
spoofed. Implement `ChainSource` over your backend (a full node, coinset.org, `chia-query`):

```rust
use dig_identity::{resolve_bls_public_key, resolve_identity_profile, ChainSource};

// `source: impl ChainSource` reads your chain honestly (it is never trusted for authority claims).
let identity = resolve_identity_profile("did:chia:1...", &source)?; // chain-authenticated
let identity_key = resolve_bls_public_key("did:chia:1...", &source)?; // slot 0x0010 BLS G1, fails closed
```

This is the seam dig-message (seal + signature) and dig-node's `DidSigningKeyResolver` consume: a DID
resolves to its BLS12-381 G1 identity key ONLY when a chain-authenticated identity actually published
one — never one attached by an unauthenticated party.

### Edit and commit the root

`set` applies an edit and returns the resulting **pending** root; the committed root (which tracks
the on-chain store root) is unchanged until `commit_root` promotes it. Building and broadcasting the
on-chain root-update spend is the chain layer's job (WU2/WU3) — this crate only computes the root.

```rust
let mut identity = identity;
let pending = identity.set(standard::BIO, Value::Utf8("builds on Chia".into()))?;
assert_ne!(pending, identity.root());        // committed root not moved yet
let committed = identity.commit_root()?;     // promote the pending root
assert_eq!(committed, pending);
# Ok::<(), dig_identity::Error>(())
```

### Prove a field

`prove_field` / `prove_field_absent` mint proofs that verify against `root()` alone (via the
crate's standalone `proof::verify_membership` / `verify_non_membership`), so a consumer can check
"this DID publishes X" or "this DID publishes no peer id" without pulling the whole profile.

```rust
let name_proof = identity.prove_field(standard::DISPLAY_NAME)?;
let no_peer_id = identity.prove_field_absent(standard::PEER_ID)?;
# Ok::<(), dig_identity::Error>(())
```

### Minting (not yet implemented)

`IdentityProfile::mint_from_did` — which launches a fresh DID and a chip35 store from it — is
**chain-gated and not yet implemented**: it returns `Error::MintNotYetImplemented`. Minting builds
on-chain spends and depends on the dig-store crate and the chain layer landing first; the signature
exists now so consumers can code against the primitive's final shape.

## License

GPL-2.0-only.
