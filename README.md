# reciprocal-kzg

This repository packages a reciprocal-folding backend project aimed at a KZG
descriptor-opening path.

The checked-in implementation is currently a Pedersen-backed PoC over a
Sonobe-derived Rust workspace. The repository name reflects the target backend
direction; it should not be read as "KZG is already implemented end to end."

## Repository Layout

- `poc/`: Sonobe-derived workspace plus reciprocal-specific implementation and integration code
- `benchmark/`: canonical benchmark artifacts for the current PoC
- `docs/`: paper note, PoC write-up, milestones, and reviewer-facing notes

## Current Status

- The reciprocal kernel, adapter, wrapper, and offchain decider paths are implemented and tested in `poc/`.
- The current opening path is Pedersen-backed.
- The next implementation milestone is a real KZG descriptor-opening library and its integration path.

## Start Here

1. `docs/reciprocal_poc.md`
2. `docs/m4_milestones.md`
3. `poc/README.md`
4. `benchmark/README.md`

## Quick Run

From `poc/`:

```powershell
cargo test -p sonobe-primitives reciprocal -- --nocapture
cargo test -p sonobe-ivc reciprocal_ -- --nocapture
cargo run -p sonobe-ivc --example reciprocal_poc
```

The canonical checked-in benchmark artifacts live at:

- `benchmark/reciprocal_snapshot.csv`
- `benchmark/reciprocal_kernel_snapshot.csv`
