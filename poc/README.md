# reciprocal-kzg PoC workspace

This directory contains the Sonobe-derived Rust workspace used for the current
reciprocal PoC.

## What Lives Here

- `crates/primitives`: reciprocal test circuits, seed-descriptor helpers, commitment code, and the kernel benchmark example
- `crates/ivc`: reciprocal adapter, wrapper, offchain decider, integration tests, and the main PoC example runner
- `crates/fs`: inherited workspace components still used by the current integration path

## Reciprocal-Specific Entry Points

- `crates/primitives/src/circuits/reciprocal_test.rs`
- `crates/primitives/examples/reciprocal_kernel_bench.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_types.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_wrapper.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_decider.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- `crates/ivc/examples/reciprocal_poc.rs`

## How To Run

```powershell
cargo test -p sonobe-primitives reciprocal -- --nocapture
cargo test -p sonobe-ivc reciprocal_ -- --nocapture
cargo run -p sonobe-primitives --example reciprocal_kernel_bench --release
cargo run -p sonobe-ivc --example reciprocal_poc
```

## Documentation

- `../docs/reciprocal_poc.md`
- `../docs/m4_milestones.md`
- `../docs/core_paper/reciprocal_fold_note.pdf`
- `../benchmark/reciprocal_snapshot.csv`
- `../benchmark/reciprocal_kernel_snapshot.csv`

## Upstream Provenance

See `UPSTREAM.md` for the workspace origin and the reciprocal-specific scope of
this repo.
