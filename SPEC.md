# dig-identity — normative specification

Version: 0.1.0 (WU1, format layer). Status: NORMATIVE.

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
| `0x0010` | signing_public_key | Bytes (32, Ed25519) |
| `0x0011` | encryption_public_key | Bytes (32, X25519 IK) |
| `0x0012` | peer_id | Bytes (32, `SHA-256(TLS SPKI DER)`) |
| `0x0013` | key_epoch | `u32` |
| `0x0018` | updated_at | `u64` (Unix seconds) |

Slots `0x0010`–`0x0013` are the DID→keys resolution set consumed by dig-chat and the dig-node
identity subsystem.

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
- **Leaf value** — a slot's leaf digest is `sha256(0x01 ‖ encoded_value)`, where `0x01` is the leaf
  domain byte and `encoded_value` is the §4 encoding. An ABSENT slot has an empty `encoded_value` and
  its leaf digest is the all-zero 32-byte value; the SMT treats an all-zero leaf as no-leaf, which is
  what makes non-membership provable.
- **Branch node** — branch nodes are hashed by the Nervos construction using sha256, with the crate's
  own merge domain-separation bytes (`0x01` normal-merge, `0x02` merge-with-zero). Implementations
  MUST reuse this construction; it is not re-specified here.

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

- **Membership** — `leaf_digest = sha256(0x01 ‖ encode(value))`. Verifying "this DID's field == X"
  requires only the root and the proof.
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

## 8. Conformance

An implementation conforms iff, for the same inputs, it reproduces: (a) every §2.1 slot key, (b)
every §4 value encoding, (c) every §5 leaf digest, merkle root, and proof (verify + reject), and (d)
every §7 pairing decision. The crate's `tests/format.rs` is the executable conformance vector set.
