use ark_std::{borrow::Borrow, rand::RngCore};
use sonobe_primitives::{relations::Relation, transcripts::Transcript};

use super::{FoldingSchemeDef, errors::Error, keys::DeciderKey};

/// Builds public parameters for a folding scheme from its external configuration.
pub trait FoldingSchemePreprocessor: FoldingSchemeDef {
    /// Produces the scheme's public parameters.
    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;
}

/// Derives prover and verifier material from public parameters and an arithmetization.
pub trait FoldingSchemeKeyGenerator: FoldingSchemeDef {
    /// Generates the decider key used by subsequent proving and verification phases.
    fn generate_keys(pp: Self::PublicParam, arith: Self::Arith) -> Result<Self::DeciderKey, Error>;
}

/// Folds running and incoming states into the next running state and a proof artifact.
pub trait FoldingSchemeProver<const M: usize, const N: usize>: FoldingSchemeDef {
    /// Produces the next running witness and instance together with the proof and challenge.
    #[allow(clippy::type_complexity)]
    fn prove(
        proving_key: &<Self::DeciderKey as DeciderKey>::ProverKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        running_witnesses: &[impl Borrow<Self::RW>; M],
        running_instances: &[impl Borrow<Self::RU>; M],
        incoming_witnesses: &[impl Borrow<Self::IW>; N],
        incoming_instances: &[impl Borrow<Self::IU>; N],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<M, N>, Self::Challenge), Error>;
}

/// Recomputes the next running instance from public data and a folding proof.
pub trait FoldingSchemeVerifier<const M: usize, const N: usize>: FoldingSchemeDef {
    /// Verifies the folding step and returns the resulting running instance.
    fn verify(
        verifying_key: &<Self::DeciderKey as DeciderKey>::VerifierKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        running_instances: &[impl Borrow<Self::RU>; M],
        incoming_instances: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, Error>;
}

/// Checks that witnesses and instances satisfy the relation expected by the scheme.
pub trait FoldingSchemeDecider: FoldingSchemeDef {
    /// Validates a running witness-instance pair.
    fn decide_running(
        decider_key: &Self::DeciderKey,
        running_witness: &Self::RW,
        running_instance: &Self::RU,
    ) -> Result<(), Error> {
        Relation::<Self::RW, Self::RU>::check_relation(
            decider_key,
            running_witness,
            running_instance,
        )
    }

    /// Validates an incoming witness-instance pair.
    fn decide_incoming(
        decider_key: &Self::DeciderKey,
        incoming_witness: &Self::IW,
        incoming_instance: &Self::IU,
    ) -> Result<(), Error> {
        Relation::<Self::IW, Self::IU>::check_relation(
            decider_key,
            incoming_witness,
            incoming_instance,
        )
    }
}

impl<FS: FoldingSchemeDef> FoldingSchemeDecider for FS {}

/// Convenience bound for folding schemes that implement the full host-side lifecycle.
pub trait FoldingSchemeOps<const M: usize, const N: usize>:
    FoldingSchemePreprocessor
    + FoldingSchemeKeyGenerator
    + FoldingSchemeProver<M, N>
    + FoldingSchemeVerifier<M, N>
    + FoldingSchemeDecider
{
}

impl<FS, const M: usize, const N: usize> FoldingSchemeOps<M, N> for FS where
    FS: FoldingSchemePreprocessor
        + FoldingSchemeKeyGenerator
        + FoldingSchemeProver<M, N>
        + FoldingSchemeVerifier<M, N>
        + FoldingSchemeDecider
{
}
