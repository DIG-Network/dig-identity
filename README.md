# dig-identity

The canonical DIG decentralized-identity **profile format**: a Chia identity anchor (a `did:chia:`
singleton in v1) paired with a chip35 DataLayer store that holds the anchor's profile as a standard,
extendable **sparse merkle tree** of slots. Each identity field lives at a fixed slot; any field can
be proved — or proved absent — against a single 32-byte root.

This crate is **WU1**: the pure, chain-independent format layer. It is keyless (never signs) and does
no chain I/O or DID resolution (those are WU2/WU3). See [`SPEC.md`](./SPEC.md) for the normative
byte-level contract.

## What it provides

- Deterministic slot-key derivation and the v1 standard slot map (+ reserved ranges, additive-only).
- A hand-rolled `tag ‖ len ‖ bytes` value encoding that Rust/JS/wasm reproduce byte-for-byte.
- A sha256 sparse merkle tree (Nervos `sparse-merkle-tree`) with membership + non-membership proofs.
- Root-only proof verification ("this DID's field == X" / "this field is absent") from `(root, proof)`.
- `DID→keys` resolution (signing / encryption / peer_id / key_epoch) — the dig-chat / dig-node seam.
- The DID↔store bidirectional-pairing predicate (description discovery + launch-from-DID authority),
  which REJECTS description-only matches.

## Example

```rust
use dig_identity::{Profile, Value, slot::standard, proof};

let mut profile = Profile::with_schema_v1();
profile.set(standard::DISPLAY_NAME, Value::Utf8("Ada".into()));

let tree = profile.build_tree()?;
let root = tree.root();

let membership = tree.prove_membership(standard::DISPLAY_NAME)?;
let claim = Value::Utf8("Ada".into());
assert!(proof::verify_membership(&root, standard::DISPLAY_NAME, &claim, &membership)?);
# Ok::<(), dig_identity::Error>(())
```

## License

GPL-2.0-only.
