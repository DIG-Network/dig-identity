# Contributing to dig-identity

Thanks for your interest in improving dig-identity. This crate defines the canonical
DIG decentralized-identity profile format — please read this before opening a PR.

## What this crate is

dig-identity is the canonical DIG decentralized-identity **profile format**: a Chia identity
anchor (a `did:chia:` singleton) paired with a chip35 DataLayer store that holds the
anchor's profile as a standard, extendable **sparse merkle tree** of slots. Each identity
field lives at a fixed slot; any field can be proved — or proved absent — against a single
32-byte root. The format core holds no network dependency; on-chain DID resolution is a
caller-supplied `ChainSource` trait seam.

## Prerequisites

- [Rust](https://rustup.rs), version **1.75** or later. Install via `rustup`.

## Build & test

```sh
# Build the library
cargo build

# Run the full test suite
cargo test --all-features

# Run doctests explicitly (doc examples must never rot)
cargo test --doc --all-features

# Build documentation
cargo doc --no-deps --all-features
```

## The gate (must pass before a PR is merged)

CI runs these on every PR (`.github/workflows/ci.yml`); run them locally before opening a PR:

```sh
# Check formatting
cargo fmt --all -- --check

# Check clippy (no warnings allowed)
cargo clippy --all-targets --all-features -- -D warnings

# Run tests with nextest (flaky-aware test runner)
cargo nextest run --all-features --retries 2 --test-threads=1

# Run doctests
cargo test --doc --all-features

# Check documentation builds
cargo doc --no-deps --all-features

# Measure coverage (must be >=80% of lines)
cargo llvm-cov nextest --all-features --workspace --fail-under-lines 80 --retries 2 --test-threads 1
```

To run coverage locally, install `cargo-llvm-cov`:

```sh
cargo install cargo-llvm-cov
```

## Commit conventions

Use Conventional Commits: `type(scope): summary`

- Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
- A breaking change appends `!` and/or a `BREAKING CHANGE:` footer
- Keep one logical change per commit where practical
- End every commit with: `Co-Authored-By: Claude <noreply@anthropic.com>`

The project enforces the format via commitlint CI; a non-conforming message will fail the PR.

## Pull requests

1. Branch from `main` with a branch name matching the Conventional Commit type (e.g. `feat/…`, `fix/…`, `docs/…`)
2. Make the gate green locally (all commands above must pass)
3. Open a PR with a clear title (Conventional Commit format) and description stating what changed and why
4. Reference any related issue
5. Keep the diff focused — one logical change per PR where practical

The main branch is protected: PRs require status checks to be green and all review threads to be resolved
before merge.
