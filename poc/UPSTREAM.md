# Upstream Provenance

This workspace is derived from the Sonobe codebase and then narrowed into the
current reciprocal-kzg PoC repository.

## Origin

- upstream project: `privacy-scaling-explorations/sonobe`
- local purpose: reuse the existing Nova plus CycleFold integration harness for reciprocal-folding experiments

## What Is Reciprocal-Specific Here

The reciprocal-specific PoC work in this repo is concentrated in:

- `crates/primitives/src/circuits/reciprocal_test.rs`
- `crates/primitives/examples/reciprocal_kernel_bench.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_types.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_wrapper.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_decider.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- `crates/ivc/examples/reciprocal_poc.rs`

## Scope Note

This workspace is the implementation root for the reciprocal PoC tracked by the
repository.
