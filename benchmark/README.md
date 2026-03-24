# benchmark

This folder contains the canonical benchmark artifacts for the current
reciprocal PoC.

It is not a separate cryptographic architecture, and it is not a standalone KZG
implementation. The current snapshot measures the same Pedersen-backed PoC
implementation against:

- the stock Sonobe test circuit
- a naive reciprocal baseline that carries descriptor metadata in state
- the specialized reciprocal path

The absence of a checked-in KZG comparison is intentional. The KZG
descriptor-opening path is the funded implementation milestone, not an existing
baseline in this repository.

## Current Contents

- `reciprocal_snapshot.csv`: canonical checked-in snapshot for the current PoC
- `reciprocal_kernel_snapshot.csv`: canonical checked-in arithmetic kernel snapshot
- `run_snapshot.ps1`: helper script to rerun the snapshot from `../poc`
- `run_kernel_snapshot.ps1`: helper script to rerun the kernel benchmark from `../poc`

## Benchmark Source

The benchmark logic lives in the PoC codebase:

- `../poc/crates/ivc/examples/reciprocal_poc.rs`
- `../poc/crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- `../poc/crates/primitives/examples/reciprocal_kernel_bench.rs`

## Artifact Roles

- `reciprocal_snapshot.csv` captures the Sonobe-integrated PoC path.
- `reciprocal_kernel_snapshot.csv` captures the paper-level arithmetic story for the reciprocal kernel itself.
