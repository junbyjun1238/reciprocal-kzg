# benchmark

This folder contains the canonical benchmark artifacts for the current
reciprocal PoC.

It is not a separate cryptographic architecture, and it is not a standalone KZG
implementation. The current snapshot measures the same Pedersen-backed PoC
implementation against:

- the stock Sonobe test circuit
- a naive reciprocal baseline that carries descriptor metadata in state
- the specialized reciprocal path

## Current Contents

- `reciprocal_snapshot.csv`: canonical checked-in snapshot for the current PoC
- `run_snapshot.ps1`: helper script to rerun the snapshot from `../poc`

## Benchmark Source

The benchmark logic lives in the PoC codebase:

- `../poc/crates/ivc/examples/reciprocal_poc.rs`
- `../poc/crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
