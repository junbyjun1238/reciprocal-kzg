# Reciprocal PoC

## What This Is

This repository contains an experimental reciprocal-folding PoC built in a
Sonobe-derived workspace.

The PoC is intentionally narrow:

- fixed same-`q` lane only
- offchain-only PoC boundary
- wrapper-level aggregated statement `(C, q, y, Pi)`
- Pedersen-backed current staging integration

This is a grant-facing backend PoC focused on the algebraic backend, statement
boundary, and opening-aware path exercised by the checked-in implementation.

For the implementation milestone plan behind the ESP grant PoC, see
`m4_milestones.md`.

For the current paper draft that this PoC is based on, see
`core_paper/reciprocal_fold_note.pdf`.

## What Was Added

### 1. Reciprocal-shaped test circuits

File:

- `crates/primitives/src/circuits/reciprocal_test.rs`

This file currently contains two circuits:

- `ReciprocalCircuitForTest`
  - exact worked `N=4` reciprocal kernel
  - uses the real round-by-round recurrence from the note
  - derives the reduced descriptor `q = mu_2` from a stored worked-instance seed
    descriptor `mu_1`
  - keeps the step state minimal
  - returns 4-coordinate external outputs
- `NaiveReciprocalCircuitForTest`
  - carries descriptor and leaf-family metadata inside the state
  - serves as a naive baseline for comparison

The worked `N=4` path stores the exact algebraic seed data needed by the
current evaluator and expands `mu_1 -> mu_2` with the note's `c = 0`
reciprocal-shift update.

### 2. Reciprocal public object / witness helpers

Files:

- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_types.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_decider.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_wrapper.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`

These layers define the PoC-level object boundary:

- public instance `(C, q, y)`
- private helper `(x, trace, omega)`
- same-`q` lane policy
- a minimal offchain decider entry point over statement shape, lane checks, and opening-aware verification
- 4-coordinate wrapper aggregation
- Pedersen-backed opening witness checks for the worked `N=4` reciprocal relation
- flattening into CycleFold-friendly public inputs

In the checked-in PoC, the `y` check is exercised through the wrapper/offchain
statement path. That is the verifier-facing boundary demonstrated by the current
integration flow.

### 3. Nova/CycleFold integration tests and snapshot benchmark

File:

- `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`

This file now also contains:

- end-to-end reciprocal integration test
- end-to-end naive reciprocal integration test
- opening-aware reciprocal statement checks in the reciprocal integration path
- rejection tests for malformed `y` and wrong `q` lane
- benchmark-style snapshot test comparing:
  - stock Sonobe test circuit
  - naive reciprocal baseline
  - specialized reciprocal same-`q` PoC

## Current Claims

This PoC currently supports the following claims:

- a real worked `N=4` reciprocal kernel can run inside Sonobe `Nova + CycleFold`
- the worked `N=4` reduced descriptor `q = mu_2` can be expanded exactly from
  stored seed data `mu_1`
- a same-`q` specialized path can be modeled with a minimal step state
- a naive state-carrying baseline is measurably heavier than the specialized path
- the wrapper/adapter boundary for `(C, q, y, Pi)` is exercised as a verifier-visible statement
- `Pi` now carries a Pedersen-backed opening witness `(x, trace, omega)` checked against `(C, q, y)`
- a minimal offchain decider can consume the current opening-aware reciprocal statement in one entry point
- malformed `y` and wrong descriptor lanes are rejected by the reciprocal statement checks

The central claim of the checked-in PoC is:

> Sonobe staging already supports a same-`q`, offchain reciprocal backend PoC
> with a real worked kernel, a verifier-visible statement boundary, and a
> concrete next step toward descriptor-consuming opening and decider hardening.

## Where To Start Reading

If you want the shortest path through the code:

1. `crates/primitives/src/circuits/reciprocal_test.rs`
2. `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_types.rs`
3. `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_wrapper.rs`
4. `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`
5. `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_decider.rs`
6. `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`

## How To Run

### Reciprocal tests

```powershell
cargo test -p sonobe-primitives reciprocal_circuit_for_test -- --nocapture
cargo test -p sonobe-ivc reciprocal_ -- --nocapture
```

### Benchmark snapshot

```powershell
cargo test -p sonobe-ivc benchmark_nova_nova_snapshot -- --ignored --nocapture
```

### Kernel benchmark

```powershell
cargo run -p sonobe-primitives --example reciprocal_kernel_bench --release
```

### Example runner

```powershell
cargo run -p sonobe-ivc --example reciprocal_poc
```

The example runner now instantiates the reciprocal circuits from the worked
seed descriptor, builds an opening-aware reciprocal statement, runs the minimal
offchain decider, and then prints the benchmark snapshot rows used by the PoC.

The canonical checked-in CSV snapshot is at
`../benchmark/reciprocal_snapshot.csv`.

The canonical arithmetic kernel snapshot is at
`../benchmark/reciprocal_kernel_snapshot.csv`.

The reciprocal kernel benchmark is intentionally separate from the Nova/CycleFold
snapshot. It measures the algebraic backend more directly:

- specialized reciprocal physical fold
- direct fixed-basis public-constant baseline
- explicit-row materialization from the reduced descriptor

The kernel benchmark verifies that all three paths agree on the worked seed and
then reports:

- the canonical multiplication counts behind the `2N - 4` claim
- the descriptor-size gap between `4(n - 1)` and explicit rows of size `4N`
- local runtime snapshots for specialized evaluation, direct baseline
  evaluation, and explicit-row materialization

## Benchmark Snapshot

Latest local snapshot from
`cargo test -p sonobe-ivc benchmark_nova_nova_snapshot -- --ignored --nocapture`:

| name | steps | state_width | step_constraints | step_witnesses | primary_constraints | avg_prove_ms | avg_verify_ms | external_output_width | q_len | adapter_public_inputs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| stock_circuit_for_test | 3 | 1 | 4 | 6 | 45304 | 1534 | 2221 | 0 | 0 | 0 |
| naive_reciprocal_stateful_test | 3 | 9 | 4 | 14 | 45916 | 1589 | 2275 | 4 | 4 | 0 |
| reciprocal_same_q_test | 3 | 1 | 0 | 2 | 45300 | 1458 | 2080 | 4 | 4 | 63 |

### How To Read The Rows

- `stock_circuit_for_test` is a reference Sonobe test circuit. It is not a reciprocal circuit.
- `naive_reciprocal_stateful_test` uses the same worked `N=4` reciprocal kernel, but carries `q` and leaf-family metadata inside the step state.
- `reciprocal_same_q_test` uses the same worked kernel under a fixed same-`q` specialization and measures the opening-aware statement surface via `adapter_public_inputs`.

### Stable Signals vs Noisy Signals

The most stable grant-facing signals are structural:

- `state_width`
- `step_witnesses`
- `primary_constraints`
- `adapter_public_inputs`

The timing columns `preprocess_ms`, `keygen_ms`, `avg_prove_ms`, and
`avg_verify_ms` are useful as rough local snapshots, but they are machine- and
run-dependent and should not be oversold.

### Grant-Facing Interpretation

- The naive reciprocal row shows the cost of carrying descriptor and leaf metadata in the step state: `state_width` rises from `1` to `9`, `step_witnesses` rises from `2` to `14`, and `primary_constraints` rises from `45300` to `45916`.
- The specialized reciprocal row keeps the same worked kernel while avoiding that state-carrying overhead: `state_width` stays at `1`, `step_witnesses` drops to `2`, and `primary_constraints` stays essentially flat against stock.
- The specialized row also exposes a real verifier-visible object: `adapter_public_inputs = 63`. That number is not "free," but it is exactly the kind of extra public surface the current PoC is supposed to make visible before a final opening layer exists.

What it shows, and why it is still useful for the grant, is that under a fixed
worked instance, the reciprocal backend is no longer a toy affine stand-in, and
the same-`q` specialized path is materially lighter than a naive state-carrying
baseline while still carrying a real verifier-visible statement boundary.

## Next Milestone

The most natural next funded step is:

- replace the Pedersen-backed PoC opening path with a descriptor-consuming opening layer
- harden the offchain decider boundary into the next real verifier component
- only then move toward final KZG and Fiat-Shamir claims

## Review Guidance

The most useful review questions at this stage are:

- Is the same-`q` specialized PoC boundary reasonable for Sonobe?
- Is the wrapper/adapter split natural enough to evolve into a real opening layer?
- Is the naive baseline fair enough as an early comparison?
- What is the cleanest next step toward a real backend integration?
