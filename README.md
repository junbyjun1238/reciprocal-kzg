# reciprocal-kzg

This repository contains a Sonobe extension for a reciprocal
descriptor-opening backend.

The current codebase is a Pedersen-backed reciprocal PoC built within a
Sonobe-derived Rust workspace. The next milestone is a KZG-backed
descriptor-opening backend.

## Repository Layout

- `poc/`: the Sonobe-derived Rust workspace and reciprocal-specific code
- `benchmark/`: canonical CSV artifacts plus rerun / reproducibility scripts
- `docs/`: the PoC write-up, milestone plan, and research note

## Start Here

1. `docs/reciprocal_poc.md`
2. `docs/m4_milestones.md`
3. `poc/README.md`
4. `benchmark/README.md`

## Run The PoC

From `poc/`:

```powershell
cargo test -p sonobe-primitives reciprocal -- --nocapture
cargo test -p sonobe-ivc reciprocal_ -- --nocapture
cargo run -p sonobe-ivc --example reciprocal_poc
```

## Benchmark Artifacts

The canonical CSV artifacts are:

- `benchmark/reciprocal_snapshot.csv`: an integration-level benchmark comparing the reference circuit, the naive reciprocal baseline, and the specialized reciprocal variant
- `benchmark/reciprocal_kernel_snapshot.csv`: a scaling benchmark for the arithmetic kernel, up to depth 16, comparing the specialized reciprocal backend against direct fixed-basis and explicit-row baselines

To reproduce the benchmark results locally after cloning:

```powershell
./benchmark/verify_repro.ps1
```

This script compares rerun outputs against the canonical CSVs on structural
metrics only. Timing columns are intentionally treated as local and
non-canonical.

## License

This repository is released under the MIT License.
