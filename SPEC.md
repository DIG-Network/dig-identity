# dig-identity — normative specification

Version: 0.4.0 (WU1 format layer + the `IdentityProfile` primitive + the WU3 chain-resolution seam +
the **v2 BLS-G1-only identity key model**).
Status: NORMATIVE.

This document is the authoritative contract for the DIG decentralized-identity **profile format** and
its **identity key model**. An independent implementation (Rust, TypeScript, or wasm) built to this
document MUST produce byte-identical slot keys, value encodings, merkle roots, proofs, key
derivations, and DH/signature primitives, and MUST make the same pairing-predicate decisions.

The format layer is **chain-independent**: it defines the pure format, the proof scheme, and the
DID↔store pairing predicate over caller-supplied records. It performs NO chain reads and resolves NO
DIDs on its own. Chain integration is a caller-supplied `ChainSource` seam (§8.2). The **BLS key
model** (§6a) adds the identity-key derivation + the seal/sign primitives, feature-gated so the pure
format still builds for wasm / no-network targets.

**Schema v2 — BLS-G1-only key model (this revision).** The identity key model is a SINGLE
Chia-compatible BLS12-381 G1 key in slot `0x0010` that does BOTH signing (BLS G2 via AugSchemeMPL)
and sealing (G1 ECDH). The prior v1 model (Ed25519 in `0x0010` + X25519 in `0x0011`) is DROPPED
ENTIRELY — no v1 read path exists. This is a sanctioned one-time pre-release schema reset: the crate
is pre-1.0 and pre-release with ZERO on-chain-anchored profiles (dig_ecosystem §3.7), so the
additive-only rule (§2.4) — which protects PUBLISHED profiles — has nothing to protect here.
`SCHEMA_VERSION_V2 = 2`. From this revision onward the additive-only rule governs all further changes.

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

### 2.2 v2 standard slot map (additive-only from this revision)

| slot_id | field | value type |
|---|---|---|
| `0x0000` | schema_version | `u16` (= 2 for v2) |
| `0x0001` | display_name | UTF-8 |
| `0x0002` | bio | UTF-8 |
| `0x0003` | avatar | UTF-8 (`dig://` URN) |
| `0x0004` | banner | UTF-8 (`dig://` URN) |
| `0x0005` | pronouns | UTF-8 |
| `0x0006` | location | UTF-8 |
| `0x0007` | links | UTF-8 (newline-separated) |
| `0x0008` | xch_address | UTF-8 (canonical mainnet `xch1…` bech32m) |
| `0x0010` | bls_g1_public_key | Bytes (48, compressed BLS12-381 G1) |
| `0x0012` | peer_id | Bytes (32, `SHA-256(TLS SPKI DER)`) |
| `0x0013` | key_epoch | `u32` |
| `0x0018` | updated_at | `u64` (Unix seconds) |

Slot `0x0010` is the **single identity key**: a 48-byte compressed BLS12-381 G1 public key
(minimal-pubkey-size) that serves BOTH uses — the sender signature (BLS G2, AugSchemeMPL) and the
seal DH (G1 ECDH). See §6a for the key model, derivation, and the sign/seal primitives. Slots
`0x0010`, `0x0012`, `0x0013` are the DID→keys resolution set consumed by dig-message, dig-chat, and
the dig-node identity subsystem.

**Slot `0x0011` is RETIRED.** In v1 it held an X25519 encryption key; the v2 model uses the ONE BLS
G1 key for both sign and seal, so `0x0011` is no longer written or read. Its id is not reused for any
other field.

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

**One-time pre-release exception (schema v2 reset).** This revision re-encodes slot `0x0010` (v1
Ed25519 → v2 48-byte BLS12-381 G1) and retires slot `0x0011` (v1 X25519). This is the ONLY sanctioned
break of the rule above, permitted because the crate is pre-1.0 and pre-release with ZERO on-chain
profiles to protect (dig_ecosystem §3.7): there are no shipped bytes to keep readable, so the rule's
protection is vacuous here. `SCHEMA_VERSION_V2 = 2` records the reset. From this revision onward the
additive-only rule is absolute — no further re-encoding, no v1 read path is (re)introduced.

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
cryptographic-key view (`bls_g1_public_key` = the 48-byte slot `0x0010` key, `peer_id`, `key_epoch`),
each OPTIONAL — a consumer MUST distinguish absent from present and MUST NOT substitute a zero-filled
default. `bls_g1_public_key` is present only when slot `0x0010` holds exactly 48 bytes.

## 6a. Identity key model — BLS12-381 G1 (NORMATIVE)

The DIG identity key is a SINGLE Chia-compatible **BLS12-381** keypair (minimal-pubkey-size): the
public key is a 48-byte compressed **G1** point (slot `0x0010`), the private key is a scalar in
`Z_r`, and a signature is a 96-byte compressed **G2** point. This ONE keypair serves both identity
uses — signing and sealing — with the safety argument in §6a.4. There is NO Ed25519 and NO X25519
anywhere in the model. Implementations MUST use the vetted `chia-bls` (derivation, sign, verify) and
`blst` (the raw G1 scalar-multiplication for ECDH + the subgroup check) primitives; they MUST NOT
hand-roll BLS or the curve arithmetic.

This section is feature-gated in the reference implementation (Cargo feature `bls`, on by default) so
the pure §1–§9 format layer still builds for a wasm / no-network target with `default-features =
false`.

### 6a.1 Derivation — the dig-identity path (wallet-controlled, non-custodial)

The identity secret key is derived from the wallet master secret via EIP-2333 hardened derivation
(`chia_bls::SecretKey::from_seed` for the master, then `DerivableKey::derive_hardened`) at the FIXED
canonical dig-identity path, all indices hardened:

```
m / 12381' / 8444' / 9' / 0'
```

- `12381'` — the BLS12-381 purpose (Chia convention).
- `8444'` — the Chia coin type.
- `9'` — the dig-identity application index (**purpose 9**), DISTINCT from Chia's wallet/coin
  key index `2'` (`m/12381'/8444'/2'/n`).
- `0'` — the identity key index within the dig-identity application.

The distinctness of `9'` from the wallet coin path `2'` is **LOAD-BEARING** (§6a.4 point 2): the
identity key derived here secures NO coins, so a confused-deputy signature on it authorizes nothing
of value. Implementations MUST derive the identity key at this exact path and MUST NOT reuse a wallet
coin-custody key as the identity key.

### 6a.2 The two uses of the one key

- **Sign — BLS G2 (AugSchemeMPL).** `sign_message(sk, msg) → [u8; 96]` produces the Chia augmented
  BLS signature (the public key is prepended and hashed to G2 with the Chia DST). `verify_signature`
  checks it against the 48-byte G1 key. dig-message signs `SIG_DOMAIN || transcript` through this
  helper ONLY — NEVER through any wallet spend-signing code path (§6a.4 point 2).
- **Seal DH — G1 ECDH.** `g1_dh(sk, peer_g1) → [u8; 48]` is scalar-multiplication on G1:
  `dh(sk, pk) = sk · pk`, serialized as the 48-byte compressed result point. It is the DH primitive of
  the DHKEM-over-G1 seal (dig-message §5.1): the sender's ephemeral encapsulation and the recipient's
  decapsulation both call it. The KDF/AEAD composition (HKDF-SHA256 + ChaCha20Poly1305, HPKE-style
  auth mode) lives in **dig-message**, not here — dig-identity provides only the raw DH, the subgroup
  check, the sign/verify, and the DID→pubkey resolution.

### 6a.3 Subgroup + non-identity validation (HARD)

Before ANY DH, a received G1 point (a resolved `bls_g1_public_key`, a peer public key, or a KEM
encapsulation) MUST be validated: it MUST deserialize as a canonical compressed point ON the curve,
it MUST lie in the prime-order `r`-subgroup (`blst` `blst_p1_affine_in_g1`), and it MUST NOT be the
identity/infinity point (nor any small-order point — which the subgroup check already excludes). A
point failing ANY check is REJECTED. `g1_subgroup_check(pk) → bool` exposes this test; `g1_dh` applies
it to `peer_g1` internally and returns `None` on failure, so a caller cannot perform a DH against an
invalid/small-subgroup point. This blocks small-subgroup / invalid-curve key-recovery attacks.

### 6a.4 Same-key sign(G2) + DH(G1) safety (NORMATIVE)

Reusing one keypair for both a G2 signature and a G1 DH is safe here, argued (not re-derived — cited
from dig-message §5.1a/§5.7):

1. **Distinct groups + distinct domains.** Signing maps the message to **G2** (`sk · H_G2(m)`) under
   the AugScheme DST; the DH is scalar-mult on **G1** (`sk · P_G1`) under the dig-message KEM info
   string `"dig-message/dhkem-g1/v1"`. The two operate in different groups with different domain
   separations; neither is an oracle for the other (a G2 signature yields no usable G1 DH value, and a
   G1 DH point is not a valid G2 signature — they even differ in size, 96 vs 48 bytes).
2. **The identity key secures no coins.** The dig-message signature domain-tag alone is insufficient
   against `AGG_SIG_UNSAFE` (which signs an attacker-chosen message with no chain suffix); the
   load-bearing defense is that the identity key is derived at a NON-wallet path (§6a.1) and therefore
   guards no funds — any confused-deputy signature authorizes nothing.
3. **Self-DH is well-defined.** When sender == recipient (self-addressed / IPC), the static DH term
   `dh(sk, sk·G1) = sk² · G1` is a valid, non-identity G1 point for any real key (`sk ≠ 0`), so seal
   and open to self succeed with no degenerate/identity result.

### 6a.5 Key-model primitives (public API)

- `IDENTITY_DERIVATION_PATH: [u32; 4]` = `[12381, 8444, 9, 0]` — the §6a.1 hardened path indices.
- `master_secret_key_from_seed(seed) → SecretKey` — the EIP-2333 master (`from_seed`).
- `derive_identity_sk(master) → SecretKey` — applies the §6a.1 hardened path to a master key.
- `g1_subgroup_check(pk: &[u8; 48]) → bool` — §6a.3.
- `g1_dh(sk: &SecretKey, peer_g1: &[u8; 48]) → Option<[u8; 48]>` — §6a.2/§6a.3 (validated DH).
- `sign_message(sk: &SecretKey, msg: &[u8]) → [u8; 96]` and
  `verify_signature(pk: &[u8; 48], msg: &[u8], sig: &[u8; 96]) → bool` — §6a.2 (AugSchemeMPL).
- `public_key_bytes(sk: &SecretKey) → [u8; 48]` — the 48-byte G1 public key for a secret key.

### 6a.6 Conformance vectors (§9)

A conforming implementation MUST reproduce: (a) the §6a.1 derivation KAT — a fixed seed → the golden
48-byte G1 public key at `m/12381'/8444'/9'/0'` (byte-agreeing with `chia-wallet-sdk`'s derivation);
(b) the §6a.2 G1-ECDH round-trip — `g1_dh(a_sk, b_pk) == g1_dh(b_sk, a_pk)`; (c) the self-DH case —
`g1_dh(sk, own_pk)` is valid and non-degenerate; (d) sign/verify round-trip + the sign/DH
domain-separation property; (e) the §6a.3 subgroup check REJECTING the identity/infinity point and a
non-subgroup point.

### 6a.7 Node/relay identity — the SAME key model, a DISTINCT per-role instance

A DIG node and a DIG relay each carry their OWN node-level BLS G1 identity key, derived through
this EXACT §6a model — the FIXED path `m/12381'/8444'/9'/0'` (slot `0x0010`), from that process's
OWN keystore master seed (`master_secret_key_from_seed` → `derive_identity_sk`). This key is used
at the transport/protocol level:

1. **Binding `peer_id` ↔ BLS public key** at the mTLS handshake (dig-nat) — the identity key proves
   who is on the other end of a peer connection.
2. **Sealing directed gossip messages** to a recipient peer (dig-gossip) — `g1_dh` (§6a.2) is the DH
   primitive of the seal, exactly as for any other DIG identity.
3. **Signing peer records** in PEX/DHT so a pre-dial verification can check the record's signer
   (§6a.2 `sign_message`/`verify_signature`).

This node/relay identity key is **NOT the user/funds identity** (the DID-anchored profile key of
§1–§7): it is a separate keypair, one per process, derived from that process's own keystore — never
the user's wallet seed. The node/relay engine never holds a user's funds key (dig-ecosystem
`CLAUDE.md` §908, the node↔user identity boundary): deriving its OWN §6a.1 identity at its OWN
process-local seed keeps that boundary intact while still reusing the identical, vetted derivation
path, sign, and seal primitives. `peer_id` (the node/relay's transport-level connection identifier)
remains distinct from this BLS identity key — the BLS key is the recipient-seal target; `peer_id`
is the routing/session handle.

No new derivation, slot, or primitive is introduced for this use — §6a.5's existing public API
(`IDENTITY_DERIVATION_PATH`, `derive_identity_sk`, `public_key_bytes`, `g1_dh`, `sign_message`,
`verify_signature`) is sufficient and is the one a node/relay implementation calls.

## 7. DID↔store pairing (bidirectional; BOTH links MANDATORY)

A store is the authoritative profile of an identity anchor only when BOTH links hold:

1. **Discovery** — the store's `description` field, trimmed, equals the anchor's DID string
   (`description == the DID string`). The v1 DID is a Chia DID: a bech32m string with the HRP
   `did:chia:` whose 32-byte payload is the DID singleton's launcher id. Parsing MUST use the
   canonical bech32m address codec (`chia-sdk-utils::Address`), so a DID byte-agrees with chip35 and
   the wallet SDK; a string that is not valid `did:chia:` bech32m is not a DID.
2. **Authority** — the store was LAUNCHED FROM the identity singleton: the store's launcher coin's
   PARENT coin is a MEMBER of the identity singleton's lineage — a genuine DID coin somewhere from the
   launcher forward to the current tip (launch-from-DID lineage). This is unforgeable and inherent at
   launch — it requires no metadata spend, no transfer/ownership layer, and no new chip35 puzzle (it is
   a launch-driver behavior; WU2).

   **Membership, NOT tip-equality (NORMATIVE).** Authority MUST be lineage membership, never equality
   with the current singleton tip. Launching a store (or NFT) from a DID parents its launcher coin to
   the DID coin AS IT EXISTED AT SPEND TIME (`Cn`), and that SAME spend RECREATES the DID singleton,
   advancing its tip to `Cn+1` (chip35 `IntermediateLauncher::new(did.coin.coin_id(), ..)` + the DID
   `update`). So the launcher parent is a PAST lineage coin (`Cn`), never the current tip (`Cn+1`).
   Binding authority to `== tip` would therefore reject EVERY legitimately-launched profile store the
   instant it is created. An implementation MUST accept a store whose launcher parent is any genuine
   lineage member. The security property is preserved: minting any coin in the victim DID's lineage
   requires the victim's key, so an attacker's coin is never a member — the link stays unforgeable.

Discovery alone is FORGEABLE — anyone may place any DID string in their store description. Therefore a
consumer MUST require BOTH links: a store that matches on discovery but whose launcher parent is NOT a
member of the DID singleton's lineage MUST be REJECTED as non-authoritative.

WU1 supplies this predicate over caller-provided records built from **canonical `chia-protocol`
types** (never hand-rolled coin/hash types):

- `StoreRecord = { description: String, launcher_coin: Coin }` — `launcher_coin.parent_coin_info` is
  the authority channel; `launcher_coin.coin_id()` is the store's launcher id.
- `SingletonLineage = { tip: Bytes32, members: Set<Bytes32> }` — the DID singleton's lineage (launcher
  → tip inclusive; `tip` is always a member). `contains(coin_id)` is the authority membership test;
  `tip()` is the current on-chain state handle.
- `IdentitySingleton = { did: Did, lineage: SingletonLineage }` — `lineage` holds the coins one of
  which an authoritative store's launcher parent must equal. `IdentitySingleton::coin_id()` returns the
  lineage tip.

`authority_matches` ⇔ `singleton.lineage.contains(store.launcher_coin.parent_coin_info)`. WU3 wires the
chain fetch that populates these records (a lineage walk from the DID launcher id forward to its
current tip).

### 7.1 Store-ownership predicate and portable proof

`store_belongs_to_did(store, singleton) -> bool` is the domain-named form of the §7 predicate: it
holds IFF BOTH links hold (discovery AND launch-from-DID lineage). Description-only or lineage-only
MUST return `false`.

`StoreOwnershipProof = { singleton: IdentitySingleton, store: StoreRecord }` is a convenience bundle
of the two records: `verify()` ⇔ `store_belongs_to_did(store, singleton)`, re-running the same
predicate.

**WU1 trust boundary (NORMATIVE — the predicate is relative, not trustless).** `singleton.did` and
`singleton.lineage` are independent, caller-supplied fields with NO internal binding: WU1 does NOT
authenticate that `lineage` is `did.launcher_id`'s real singleton lineage. The pairing/ownership
decision is therefore SOUND ONLY RELATIVE TO a `lineage` — and a `root` (§8) — the verifier has
INDEPENDENTLY resolved on-chain. A producer who supplies their OWN singleton's lineage, with a store
they launched from it whose `description` names a victim DID, obtains `store_belongs_to_did == true` and
`StoreOwnershipProof::verify() == true` — a spoof of the victim DID. Consequently:

- `StoreOwnershipProof` is NOT a self-authenticating, trustless attestation, and MUST NOT be trusted
  from an untrusted producer. A `true` means only "these records satisfy the predicate", not "this
  store is chain-authenticated as the DID's profile".
- WU3 MUST resolve `singleton.lineage` as `did.launcher_id`'s authentic singleton lineage (launcher →
  tip), and the §8 `root` as THIS store's authentic current on-chain `root_hash`, before any consumer
  relies on the decision. Producing a portable proof whose `lineage` is chain-bound to the DID is WU3's
  job.

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
the identity singleton (§7 `IdentitySingleton` = DID + caller-resolved singleton lineage), the paired
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
  a `singleton.lineage` the caller resolved on-chain (WU3); `resolve` does NOT authenticate `lineage`
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
`IdentityProfile` whose `singleton.lineage` and profile `root` are BOTH derived from the DID via an
honest chain read, so a consumer may trust the resolved DID authority and keys. It is expressed as a
caller-supplied `ChainSource` TRAIT, so the crate remains chain- and network-independent (it still
builds for wasm / no-network targets — the network dependency lives in the consumer's implementation).

The `ChainSource` trait an implementation MUST provide (an honest reader of chain state — a full node
/ coinset client, never an attacker-controlled channel):

- `resolve_singleton_lineage(launcher_id) -> Option<SingletonLineage>` — walks the singleton lineage
  from `launcher_id` forward to its current unspent tip, returning EVERY coin id on that walk (a
  `SingletonLineage` whose `tip` is the current coin), or `None` if unlaunched/melted. The caller
  implements the walk against its own chain backend (coinset / full node).
- `find_stores_for_did(did) -> Vec<ChainStoreState>` — every store whose CURRENT on-chain description
  names `did` (a discovery scan; over-returning is safe, authority is re-checked).
- `fetch_profile(store, root_hash) -> Profile` — the store's current profile body (untrusted until
  bound to `root_hash`).

`ChainStoreState = { store: StoreRecord, root_hash: Bytes32 }` (the §7 pairing record plus the store
singleton's current on-chain committed root).

The resolution algorithm (each step trust-critical), which a conforming implementation MUST perform:

1. Parse the DID → `launcher_id` (§ the canonical bech32m codec); a non-`did:chia:` input is
   `InvalidDid`.
2. Resolve the AUTHENTIC singleton lineage by walking `launcher_id`'s lineage from the launcher to its
   tip; every coin id on that walk is the ONLY authority trusted as `IdentitySingleton.lineage`. It is
   derived from the DID, NEVER accepted from a producer — this is what defeats authority-laundering. No
   lineage → `NoIdentitySingleton`.
3. Keep only discovered candidates that satisfy the FULL §7.1 pairing predicate (description names the
   DID AND launcher parent is a MEMBER of the step-2 lineage — see §7's membership-not-tip-equality
   rule). Zero → `NoProfile`; more than one → `AmbiguousProfile`.
4. Bind the chosen store's fetched profile body to its current on-chain `root_hash`; a body that hashes
   to a different root is `StaleOrTamperedRoot`. Only then are the profile key slots (§6) trusted.

Public entry points:

- `resolve_identity_profile(did_uri, source) -> Result<IdentityProfile, ResolveError>` — the full
  chain-authenticated resolution above.
- `resolve::resolve_did_keys(did_uri, source) -> Result<DidKeys, ResolveError>` — the §6 key set of the
  chain-authenticated profile.
- `resolve_bls_public_key(did_uri, source) -> Result<[u8; 48], ResolveError>` — slot `0x0010`, the
  48-byte compressed BLS12-381 G1 identity key; the exact seam dig-message (seal + sig) and a dig-node
  `DidSigningKeyResolver` consume; `NoIdentityKey` when the authoritative profile publishes none. The
  returned bytes are the on-chain-published key; a consumer that intends to DH against it MUST still
  run the §6a.3 subgroup check (`g1_dh` does this internally).

Every failure fails CLOSED (`ResolveError`): `InvalidDid`, `NoIdentitySingleton`, `NoProfile`,
`AmbiguousProfile`, `StaleOrTamperedRoot`, `NoIdentityKey`, `Format`, `Chain`. A resolver NEVER yields
authority it could not fully authenticate against the chain.

The DID→dig-store minting driver (WU2, `mint_from_did`) remains a follow-on (§8.1).

## 9. Conformance

An implementation conforms iff, for the same inputs, it reproduces: (a) every §2.1 slot key, (b)
every §4 value encoding, (c) every §5 leaf digest, merkle root, and proof (verify + reject), (d)
every §7 pairing and §7.1 ownership decision, (e) every §8 composed-verification decision, and (f)
every §6a key-model vector (derivation KAT, G1-ECDH round-trip, self-DH, sign/verify + domain
separation, subgroup-reject). The crate's `tests/format.rs` and `tests/bls_key_model.rs` are the
executable conformance vector set.

This revision RESETS the key model to schema v2 (§2.2/§2.4): slot `0x0010` is re-encoded from
Ed25519 to a 48-byte BLS12-381 G1 key and slot `0x0011` (X25519) is retired — a sanctioned one-time
pre-release break (zero on-chain profiles, dig_ecosystem §3.7). From this revision onward the
additive-only rule (§2.4) governs all further changes.
