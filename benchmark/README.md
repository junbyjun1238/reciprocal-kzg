# benchmark

This folder contains the comparison layer for the reciprocal backend.

It is not a separate cryptographic architecture. The benchmark path measures the
same PoC/backend implementation against:

- the stock Sonobe test circuit
- a naive reciprocal baseline that carries descriptor metadata in state
- the specialized reciprocal path

## Current Contents

- `reciprocal_snapshot.csv`: latest checked-in snapshot
- `run_snapshot.ps1`: helper script to rerun the benchmark from `../poc`

## Benchmark Source

The current benchmark logic lives in the PoC codebase:

- `../poc/crates/ivc/examples/reciprocal_poc.rs`
- `../poc/crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
