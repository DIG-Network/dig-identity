# dig-identity — normative specification

Version: 0.3.0 (WU1 format layer + the `IdentityProfile` primitive + the WU3 chain-resolution seam).
Status: NORMATIVE.

This document is the authoritative contract for the DIG decentralized-identity **profile format**. An
independent implementation (Rust, TypeScript, or wasm) built to this document MUST produce
byte-identical slot keys, value encodings, merkle roots, and proofs, and MUST make the same
pairing-predicate decisions.

WU1 is **chain-independent**: it defines the pure format, the proof scheme, and the DID↔store
pairing predicate over caller-supplied records. It performs NO chain reads, holds NO signing keys,
and resolves NO DIDs. Chain integration (launch-from-DID drivers, DID→store resolution) is specified
by WU2/WU3 and is out of scope here.

## 1. Model

A DIG identity is an **identity anchor** — a Chia singleton, whose v1 concrete form is a `did:chia:`
decentralized identifier — PAIRED with a chip35 DataLayer store that holds the anchor's **profile**.

The profile is a **256-bit-keyed sparse merkle tree (SMT)**. Each identity field occupies a fixed
**slot**; a slot is addressed in the tree by its derived 256-bit **slot key**. The SMT root is a
single 32-byte commitment to the entire profile and supports compact **membership** and
**non-membership** proofs. The SMT root is DEFINED by this format; WU3 pairs it with the paired
DataStore singleton's on-chain `root_hash`.

The merkle construction is the audited Nervos `sparse-merkle-tree` crate (v0.6). Implementations MUST
reproduce that construction; this spec does not re-derive it. The only hash injected into the tree is
sha256 (§3). Chia coin/hash types are the canonical `chia-protocol` types (`Bytes32`, `Coin`), pinned
to the ecosystem line (chip35, dig-block) — never hand-rolled — so lineage records byte-agree.

## 2. Slots

### 2.1 Slot key derivation

A slot is identified by a 16-bit `slot_id`. Its tree key is:

```
slot_key = sha256("dig-identity:slot:" ‖ u32_be(slot_id))
```

where `"dig-identity:slot:"` is the ASCII domain string (no NUL terminator) and `u32_be(slot_id)` is
the slot id widened to a 4-byte big-endian unsigned integer. The widening to `u32` is fixed forever
even though ids fit in `u16`.

### 2.2 v1 standard slot map (fixed forever, additive-only)

| slot_id | field | value type |
|---|---|---|
| `0x0000` | schema_version | `u16` (= 1 for v1) |
| `0x0001` | display_name | UTF-8 |
| `0x0002` | bio | UTF-8 |
| `0x0003` | avatar | UTF-8 (`dig://` URN) |
| `0x0004` | banner | UTF-8 (`dig://` URN) |
| `0x0005` | pronouns | UTF-8 |
| `0x0006` | location | UTF-8 |
| `0x0007` | links | UTF-8 (newline-separated) |
| `0x0008` | xch_address | UTF-8 (canonical mainnet `xch1…` bech32m) |
| `0x0010` | signing_public_key | Bytes (32, Ed25519) |
| `0x0011` | encryption_public_key | Bytes (32, X25519 IK) |
| `0x0012` | peer_id | Bytes (32, `SHA-256(TLS SPKI DER)`) |
| `0x0013` | key_epoch | `u32` |
| `0x0018` | updated_at | `u64` (Unix seconds) |

Slots `0x0010`–`0x0013` are the DID→keys resolution set consumed by dig-chat and the dig-node
identity subsystem.

Slot `0x0008` (`xch_address`) is the identity's XCH receive address — the $DIG-payments seam (tip
or pay an identity). Its value is the bech32m address string, and a reader MUST accept it only when
it decodes as a **canonical mainnet XCH address**: the human-readable prefix is exactly `xch`, the
Bech32m checksum verifies, and the payload is a 32-byte puzzle hash. Validation MUST use the
canonical bech32m address codec (`chia-sdk-utils::Address`); a wrong HRP (e.g. testnet `txch`), a bad
checksum, or a non-32-byte payload is REJECTED (the typed accessor returns absent).

### 2.3 Reserved ranges

| range | purpose |
|---|---|
| `0x0000`–`0x00FF` | future STANDARD slots (defined by this crate) |
| `0x0100`–`0x0FFF` | ecosystem-extension slots |
| `0x1000`–`0xEFFF` | application-defined custom slots |
| `0xF000`–`0xFFFF` | encrypted slots (reserved for the v2 privacy layer) |

### 2.4 Additive-only rule (HARD)

The slot map is a permanent, on-chain-anchored contract (the §5.1 back-compat spirit of the DIG store
format). New capability is added ONLY by allocating a new slot id. An existing slot id MUST NOT be
renumbered, repurposed, or re-encoded. A reader MUST IGNORE slot ids it does not recognize rather than
reject the profile, so an older reader keeps functioning against a newer writer's tree.

## 3. Hashing

All hashing is sha256. Three domains are kept separate:

- **Slot key** — `sha256("dig-identity:slot:" ‖ u32_be(slot_id))` (§2.1).
- **Leaf value** — a slot's leaf digest is `sha256(0x01 ‖ slot_key ‖ encoded_value)`, where `0x01` is
  the leaf domain byte, `slot_key` is the slot's 32-byte key (§2.1), and `encoded_value` is the §4
  encoding. An ABSENT slot has an empty `encoded_value` and its leaf digest is the all-zero 32-byte
  value (regardless of `slot_key`); the SMT treats an all-zero leaf as no-leaf, which is what makes
  non-membership provable.
- **Branch node** — branch nodes are hashed by the Nervos construction using sha256, with the crate's
  own merge domain-separation bytes (`0x01` normal-merge, `0x02` merge-with-zero). Implementations
  MUST reuse this construction; it is not re-specified here.

**Leaf/branch domain separation (rationale).** The `0x01` leaf-domain byte alone does NOT guarantee
non-confusion between a leaf preimage and a branch preimage: the Nervos `MERGE_NORMAL` branch preimage
also begins with `0x01`, and because a `Bytes` value payload (§4) is attacker-chosen, a leaf preimage
could in principle be crafted byte-identical to a branch preimage. That collision is non-exploitable
in a merkle proof because the verifier folds every leaf from height 0 up to 256 — its **depth
accounting**, not the leading byte, is what actually separates leaves from branches. To make the
separation SELF-CONTAINED (independent of the tree crate's internals, for a second JS/wasm
implementation), the 32-byte `slot_key` is bound into the leaf preimage: a leaf preimage carries the
fixed `dig-identity` slot key that no branch preimage carries. This binding is part of the FROZEN v1
format.

## 4. Value encoding

Slot values use a deterministic hand-rolled `tag ‖ len ‖ payload` encoding (NOT serde/CBOR) so all
implementations agree byte-for-byte:

```
┌─────────┬───────────────┬───────────────┐
│ tag: u8 │ len: u32 (be) │ payload: len  │
└─────────┴───────────────┴───────────────┘
```

- `tag` — the value type (§4.1).
- `len` — the big-endian `u32` byte length of `payload`.
- `payload` — the raw value bytes.

The minimum encoded length is 5 bytes (header only, empty payload). A decoder MUST reject a blob
whose `payload` length differs from `len`, whose `tag` is undefined, or (for fixed-width tags) whose
`payload` width differs from the tag's mandated width.

### 4.1 Value tags

| tag | type | payload |
|---|---|---|
| `0x01` | Utf8 | UTF-8 bytes (MUST be valid UTF-8) |
| `0x02` | Bytes | opaque bytes |
| `0x03` | U16 | 2 bytes, big-endian |
| `0x04` | U32 | 4 bytes, big-endian |
| `0x05` | U64 | 8 bytes, big-endian |

Fixed-width tags (`0x03`/`0x04`/`0x05`) MUST carry exactly 2/4/8 payload bytes respectively.

## 5. Proofs

A proof is the Nervos compiled-merkle-proof byte string for a single slot key. Verification is
**root-only**: given `(root, slot_id, claimed value | absence, proof)` a verifier reconstructs the
root from the leaf `(slot_key, leaf_digest)` and accepts iff the reconstruction equals `root`. No
access to the tree is required.

- **Membership** — `leaf_digest = sha256(0x01 ‖ slot_key ‖ encode(value))`. Verifying "this DID's
  field == X" requires only the root and the proof.
- **Non-membership** — `leaf_digest = 0x00…00` (32 zero bytes). This proves a slot is ABSENT and is
  REQUIRED (dig-chat must distinguish "no encryption key present" from a present key).

Soundness properties (tested):

- A tampered claimed value reconstructs a different root → REJECT.
- A proof minted for slot A does not verify a claim about slot B (cross-slot replay) → REJECT.
- A present slot does not verify as absent, and vice versa.

## 6. Profile reads and key resolution

A `Profile` is the set of `(slot_id, value)` pairs. Its root is the SMT root of the materialized
tree. Standard typed accessors decode the standard slots; `resolve_did_keys` extracts the
cryptographic-key view (`signing_public_key`, `encryption_public_key`, `peer_id`, `key_epoch`), each
OPTIONAL — a consumer MUST distinguish absent from present and MUST NOT substitute a zero-filled
default.

## 7. DID↔store pairing (bidirectional; BOTH links MANDATORY)

A store is the authoritative profile of an identity anchor only when BOTH links hold:

1. **Discovery** — the store's `description` field, trimmed, equals the anchor's DID string
   (`description == the DID string`). The v1 DID is a Chia DID: a bech32m string with the HRP
   `did:chia:` whose 32-byte payload is the DID singleton's launcher id. Parsing MUST use the
   canonical bech32m address codec (`chia-sdk-utils::Address`), so a DID byte-agrees with chip35 and
   the wallet SDK; a string that is not valid `did:chia:` bech32m is not a DID.
2. **Authority** — the store was LAUNCHED FROM the identity singleton: the store's launcher coin's
   PARENT coin IS the identity singleton coin (launch-from-DID lineage). This is unforgeable and
   inherent at launch — it requires no metadata spend, no transfer/ownership layer, and no new chip35
   puzzle (it is a launch-driver behavior; WU2).

Discovery alone is FORGEABLE — anyone may place any DID string in their store description. Therefore a
consumer MUST require BOTH links: a store that matches on discovery but NOT on launcher-parent lineage
MUST be REJECTED as non-authoritative.

WU1 supplies this predicate over caller-provided records built from **canonical `chia-protocol`
types** (never hand-rolled coin/hash types):

- `StoreRecord = { description: String, launcher_coin: Coin }` — `launcher_coin.parent_coin_info` is
  the authority channel; `launcher_coin.coin_id()` is the store's launcher id.
- `IdentitySingleton = { did: Did, coin_id: Bytes32 }` — `coin_id` is the identity singleton coin an
  authoritative store's launcher parent must equal.

`authority_matches` ⇔ `store.launcher_coin.parent_coin_info == singleton.coin_id`. WU3 wires the chain
fetch that populates these records (one launcher-parent lookup per store, resolving the DID's launcher
id to its current singleton coin).

### 7.1 Store-ownership predicate and portable proof

`store_belongs_to_did(store, singleton) -> bool` is the domain-named form of the §7 predicate: it
holds IFF BOTH links hold (discovery AND launch-from-DID lineage). Description-only or lineage-only
MUST return `false`.

`StoreOwnershipProof = { singleton: IdentitySingleton, store: StoreRecord }` is a convenience bundle
of the two records: `verify()` ⇔ `store_belongs_to_did(store, singleton)`, re-running the same
predicate.

**WU1 trust boundary (NORMATIVE — the predicate is relative, not trustless).** `singleton.did` and
`singleton.coin_id` are independent, caller-supplied fields with NO internal binding: WU1 does NOT
authenticate that `coin_id` is `did.launcher_id`'s real singleton coin. The pairing/ownership decision
is therefore SOUND ONLY RELATIVE TO a `coin_id` — and a `root` (§8) — the verifier has INDEPENDENTLY
resolved on-chain. A producer who supplies their OWN launcher coin as `coin_id`, with a store they
launched from it whose `description` names a victim DID, obtains `store_belongs_to_did == true` and
`StoreOwnershipProof::verify() == true` — a spoof of the victim DID. Consequently:

- `StoreOwnershipProof` is NOT a self-authenticating, trustless attestation, and MUST NOT be trusted
  from an untrusted producer. A `true` means only "these records satisfy the predicate", not "this
  store is chain-authenticated as the DID's profile".
- WU3 MUST resolve `singleton.coin_id` as `did.launcher_id`'s authentic CURRENT singleton coin, and
  the §8 `root` as THIS store's authentic current on-chain `root_hash`, before any consumer relies on
  the decision. Producing a portable proof whose `coin_id` is chain-bound to the DID is WU3's job.

(The conformance vector `store_ownership_proof_is_relative_to_a_trusted_coin_id_not_trustless` pins
this limitation.)

## 8. Composed field verification ("this datum belongs to this DID")

The consumer-facing question — *does this profile field belong to DID D?* — is answered by composing
the §7 pairing predicate with a §5 proof; BOTH MUST hold:

- `verify_profile_field_for_did(singleton, store, root, slot, value, proof)` accepts IFF `store`
  belongs to `singleton` (§7.1) AND `proof` proves `(slot, value)` against `root` (§5 membership).
- `verify_profile_field_absent_for_did(singleton, store, root, slot, proof)` accepts IFF `store`
  belongs to `singleton` AND `proof` proves `slot` is ABSENT against `root` (§5 non-membership).

Both are **accept-only**: acceptance is the single success value `Ok(true)`, and every non-acceptance
is an explicit error — `NotAuthoritativeProfile` (pairing failed) or `FieldProofRejected` (the merkle
proof did not verify) — never a silent `Ok(false)`. `root` is the store's authoritative profile root,
supplied by the caller (WU3 fetches it on-chain; WU1 is networkless). Per the §7.1 trust boundary, a
membership proof is only meaningful against the store's authentic current on-chain `root_hash`: a
valid proof against an unrelated `root` gives a false accept, so WU3 MUST resolve `root` (and
`singleton.coin_id`) before a consumer relies on the result.

## 8.1 The `IdentityProfile` primitive (the managed DID + store + SMT triple)

`IdentityProfile` is the managed object that composes the three pieces a DIG identity is at rest —
the identity singleton (§7 `IdentitySingleton` = DID + caller-resolved singleton coin id), the paired
chip35 DataLayer store (§7 `StoreRecord`), and the profile SMT (§6 `Profile`) with its current
committed root — into one lifecycle. It **wraps** `Profile` (which is unchanged and still the metadata
slot-map consumers read directly); it does NOT replace it. It adds only lifecycle wiring over the
already-normative §5/§6/§7/§8 primitives and introduces no new trust.

Networkless surface (WU1 — implemented now):

- `IdentityProfile::resolve(singleton, store, metadata) -> Result<Self>` — constructs the primitive
  ONLY when the §7.1 pairing predicate holds over the supplied records (`store_belongs_to_did`);
  otherwise `Err(NotAuthoritativeProfile)`. A description-only or lineage-only store is REJECTED, so an
  `IdentityProfile` value cannot exist for an unpaired/spoofed store. The committed root is computed
  from `metadata` (§5/§6). This inherits the §7.1 **trust boundary VERBATIM**: soundness is relative to
  a `singleton.coin_id` the caller resolved on-chain (WU3); `resolve` does NOT authenticate `coin_id`
  and MUST NOT be construed as chain authentication.
- `set(slot, value) -> Result<root>` — edits the in-memory metadata and returns the resulting
  **pending** root; the committed root is unchanged until `commit_root`.
- `commit_root() -> Result<root>` — recomputes the metadata root and promotes it to the committed
  root (the root a caller then commits on-chain). Building/broadcasting the chip35 update-root spend
  is WU2/WU3; WU1 computes only the root.
- `store_belongs_to_did() -> bool`, `prove_field(slot)`, `prove_field_absent(slot)` — thin over §7.1
  and §5; proofs verify against `root()` by the standalone §5 verifiers.
- Read accessors — `did()`, `singleton()`, `store()`, `metadata()`, `root()`, `keys()` (§6),
  `xch_address()`, `display_name()` — delegate to the inner records.

Chain-gated surface (STUBBED):

- `mint_from_did(did_coin, owner_puzzle_hash, seed_metadata) -> Result<Self>` — launches a DID and a
  chip35 store launched FROM it (launch-from-DID lineage, §7). It is **NOT YET IMPLEMENTED** and MUST
  return the typed `MintNotYetImplemented` error. Minting is GATED on the dig-store crate and the WU3
  chain layer; dig-identity MUST NOT depend on dig-store (the dependency graph stays acyclic), so the
  launch driver ships as a WU2 follow-on. The signature exists now so consumers code against the final
  shape; when the gate lifts it will additionally yield the launch spend bundle and take the owner
  delegation.

## 8.2 On-chain DID resolution (WU3)

WU3 closes the §7.1/§8.1 trust boundary: it turns a `did:chia:` string into a **chain-authenticated**
`IdentityProfile` whose `singleton.coin_id` and profile `root` are BOTH derived from the DID via an
honest chain read, so a consumer may trust the resolved DID authority and keys. It is expressed as a
caller-supplied `ChainSource` TRAIT, so the crate remains chain- and network-independent (it still
builds for wasm / no-network targets — the network dependency lives in the consumer's implementation).

The `ChainSource` trait an implementation MUST provide (an honest reader of chain state — a full node
/ coinset client, never an attacker-controlled channel):

- `resolve_singleton_tip(launcher_id) -> Option<Coin>` — walks the singleton lineage from
  `launcher_id` to its current unspent tip coin, or `None` if unlaunched/melted.
- `find_stores_for_did(did) -> Vec<ChainStoreState>` — every store whose CURRENT on-chain description
  names `did` (a discovery scan; over-returning is safe, authority is re-checked).
- `fetch_profile(store, root_hash) -> Profile` — the store's current profile body (untrusted until
  bound to `root_hash`).

`ChainStoreState = { store: StoreRecord, root_hash: Bytes32 }` (the §7 pairing record plus the store
singleton's current on-chain committed root).

The resolution algorithm (each step trust-critical), which a conforming implementation MUST perform:

1. Parse the DID → `launcher_id` (§ the canonical bech32m codec); a non-`did:chia:` input is
   `InvalidDid`.
2. Resolve the AUTHENTIC singleton coin by walking `launcher_id`'s lineage to its tip; its coin id is
   the ONLY value trusted as `IdentitySingleton.coin_id`. It is derived from the DID, NEVER accepted
   from a producer — this is what defeats authority-laundering. No tip → `NoIdentitySingleton`.
3. Keep only discovered candidates that satisfy the FULL §7.1 pairing predicate (description names the
   DID AND launcher parent == the step-2 coin). Zero → `NoProfile`; more than one → `AmbiguousProfile`.
4. Bind the chosen store's fetched profile body to its current on-chain `root_hash`; a body that hashes
   to a different root is `StaleOrTamperedRoot`. Only then are the profile key slots (§6) trusted.

Public entry points:

- `resolve_identity_profile(did_uri, source) -> Result<IdentityProfile, ResolveError>` — the full
  chain-authenticated resolution above.
- `resolve::resolve_did_keys(did_uri, source) -> Result<DidKeys, ResolveError>` — the §6 key set of the
  chain-authenticated profile.
- `resolve_signing_key(did_uri, source) -> Result<[u8; 32], ResolveError>` — slot `0x0010`, the exact
  seam a dig-node `DidSigningKeyResolver` consumes; `NoSigningKey` when the authoritative profile
  publishes none.

Every failure fails CLOSED (`ResolveError`): `InvalidDid`, `NoIdentitySingleton`, `NoProfile`,
`AmbiguousProfile`, `StaleOrTamperedRoot`, `NoSigningKey`, `Format`, `Chain`. A resolver NEVER yields
authority it could not fully authenticate against the chain.

The DID→dig-store minting driver (WU2, `mint_from_did`) remains a follow-on (§8.1).

## 9. Conformance

An implementation conforms iff, for the same inputs, it reproduces: (a) every §2.1 slot key, (b)
every §4 value encoding, (c) every §5 leaf digest, merkle root, and proof (verify + reject), (d)
every §7 pairing and §7.1 ownership decision, and (e) every §8 composed-verification decision. The
crate's `tests/format.rs` is the executable conformance vector set.

This revision FREEZES the v1 format ahead of the first release: the `0x0008` slot, the ownership
predicate/proof, and the composed-verify APIs are additive; the slot-key-bound leaf digest (§3) is a
pre-release finalization of the leaf hashing (the crate is unreleased with no consumers, so it breaks
no shipped `.dig`/profile bytes). From the first release onward the additive-only rule (§2.4) governs
all further changes.
