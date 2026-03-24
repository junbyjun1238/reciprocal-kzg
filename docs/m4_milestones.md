# ESP Grant M1-M4 Milestones

## Goal

Build the reciprocal backend into a real KZG descriptor-opening library and wire
that path into the current Sonobe-derived integration flow.

This milestone plan is implementation-focused. The deliverables are code,
integration paths, tests, and demo artifacts.

## M1. KZG Descriptor-Opening Library

### Build

- implement a KZG-backed commitment and opening module for reciprocal descriptor queries
- implement commit, query, open, and verify paths for the reciprocal input and reduced descriptor
- expose an API that can replace the current Pedersen-backed PoC path

### Deliverables

- KZG-backed reciprocal commitment and opening module
- open and verify API for descriptor queries
- unit tests and worked-instance tests

### Acceptance

- reciprocal inputs can be committed under the new KZG path
- a reduced-descriptor query can produce an opening proof
- verification rejects wrong output, wrong descriptor, and wrong opening
- the example flow no longer depends on the Pedersen-only reciprocal opening path

## M2. Sonobe Adapter Integration

### Build

- wire the KZG-backed reciprocal proof path into the current adapter flow
- replace the current PoC opening boundary in the example and integration paths
- update integration tests so they exercise the new library path directly

### Deliverables

- reciprocal adapter path backed by the KZG library
- updated integration tests
- updated example runner

### Acceptance

- reciprocal statements are generated through the new library path
- integration tests exercise the new proof path directly
- malformed output, wrong descriptor, and wrong opening are rejected inside the integrated path
- the example runner demonstrates the new flow end to end

## M3. Aggregation Path

### Build

- implement a real aggregation path for the `F^4` reciprocal outputs
- make the aggregated reciprocal object the default artifact produced by the example and test paths

### Deliverables

- 4-coordinate aggregation path
- aggregated proof object and verification helpers
- aggregation-path tests

### Acceptance

- the verifier consumes an aggregated reciprocal proof object rather than ad hoc helper outputs
- the example and tests use the aggregated path by default

## M4. Decider Hardening and Grant Demo Package

### Build

- upgrade the current helper-style offchain decider into a library entry point over the aggregated proof object
- connect aggregation, opening checks, and fold linkage in one verifier path
- refresh the benchmark package around the KZG-backed path
- rerun the naive-versus-specialized comparison with the updated backend path
- prepare reviewer-facing run instructions and a clean end-to-end demo flow

### Deliverables

- refreshed benchmark snapshot
- refreshed kernel benchmark snapshot
- reviewer run guide
- end-to-end demo command set

### Acceptance

- one decider entry point checks relation consistency, opening consistency, and fold linkage
- a reviewer can run the main demo flow from the repository without extra interpretation
- the checked-in benchmark snapshot reflects the KZG-backed path
- the repo clearly shows which code is the library, which path is the integration flow, and which artifacts are benchmark outputs
