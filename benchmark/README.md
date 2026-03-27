# benchmark

This folder contains the canonical benchmark artifacts for the current
reciprocal PoC.

The current snapshot measures the checked-in PoC implementation against:

- the stock Sonobe test circuit
- a naive reciprocal baseline that carries descriptor metadata in state
- the specialized reciprocal path

## Current Contents

- `reciprocal_snapshot.csv`: canonical checked-in snapshot for the current PoC
- `reciprocal_kernel_snapshot.csv`: canonical checked-in arithmetic kernel snapshot
- `run_snapshot.ps1`: helper script to rerun the snapshot from `../poc`
- `run_kernel_snapshot.ps1`: helper script to rerun the kernel benchmark from `../poc`
- `verify_repro.ps1`: reruns both benchmark tracks and checks that the structural metrics still match the checked-in CSVs

## Benchmark Source

The benchmark logic lives in the PoC codebase:

- `../poc/crates/ivc/examples/reciprocal_poc.rs`
- `../poc/crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- `../poc/crates/primitives/examples/reciprocal_kernel_bench.rs`

## Artifact Roles

- `reciprocal_snapshot.csv` captures the Sonobe-integrated PoC path.
- `reciprocal_kernel_snapshot.csv` captures the paper-level arithmetic story for the reciprocal kernel itself.

## Reproducibility Note

The checked-in CSVs are canonical for structural metrics such as state width,
witness counts, constraint counts, descriptor sizes, and multiplication counts.
Local timing columns are expected to vary across machines and runs, so
`verify_repro.ps1` compares only the structural columns when checking whether a
fresh clone reproduces the same benchmark conclusions.
