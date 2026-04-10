use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sonobe_primitives::arithmetizations::ArithConfig;

/// Bundles the proving, verifying, and arithmetic material needed by a folding decider.
pub trait DeciderKey: CanonicalSerialize + CanonicalDeserialize {
    type ProverKey;
    type VerifierKey;
    type ArithConfig: ArithConfig;

    /// Returns the proving material used by fold/prove operations.
    fn prover_key(&self) -> &Self::ProverKey;

    /// Returns the verifying material used by verify operations.
    fn verifier_key(&self) -> &Self::VerifierKey;

    /// Returns the arithmetic configuration that shapes dummy values and assignments.
    fn arith_config(&self) -> &Self::ArithConfig;
}
