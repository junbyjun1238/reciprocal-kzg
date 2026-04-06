# benchmark

This folder contains the canonical benchmark artifacts for the public PoC.

The integration-level snapshot compares:

- the reference Sonobe test circuit
- a naive reciprocal baseline that carries descriptor metadata in state
- the specialized reciprocal variant

## Current Contents

- `reciprocal_snapshot.csv`: canonical integration-level snapshot for the current PoC
- `reciprocal_kernel_snapshot.csv`: canonical arithmetic-kernel snapshot
- `run_snapshot.ps1`: helper script to rerun the snapshot from `../poc`
- `run_kernel_snapshot.ps1`: helper script to rerun the kernel benchmark from `../poc`
- `verify_repro.ps1`: reruns both benchmark tracks and checks that the structural metrics still match the canonical CSVs

## Benchmark Source

The benchmark code lives in the PoC workspace:

- `../poc/crates/ivc/examples/reciprocal_poc.rs`
- `../poc/crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- `../poc/crates/primitives/examples/reciprocal_kernel_bench.rs`

## Artifact Roles

- `reciprocal_snapshot.csv` captures the Sonobe-integrated benchmark for the current PoC.
- `reciprocal_kernel_snapshot.csv` captures the arithmetic scaling benchmark for the reciprocal kernel itself.

## Reproducibility Note

The CSVs are treated as canonical for structural metrics such as state width,
witness counts, constraint counts, descriptor sizes, and multiplication counts.
Local timing columns are expected to vary across machines and runs, so
`verify_repro.ps1` compares only the structural columns when checking whether a
fresh clone reproduces the same benchmark conclusions.
