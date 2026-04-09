use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    arithmetizations::Error as ArithError, commitments::Error as CommitmentError,
};
use thiserror::Error;

/// Shared error surface for folding-scheme setup, proving, verification, and gadget synthesis.
#[derive(Debug, Error)]
pub enum Error {
    /// Forwards arithmetic failures produced by the underlying arithmetization layer.
    #[error(transparent)]
    ArithError(#[from] ArithError),
    /// Forwards commitment failures produced by the underlying commitment layer.
    #[error(transparent)]
    CommitmentError(#[from] CommitmentError),
    /// Forwards constraint-system failures raised while synthesizing gadgets.
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    /// Reports that the requested folding workflow is not supported by this implementation.
    #[error("Unsupported use case: {0}")]
    Unsupported(String),
    /// Reports that the evaluation domain required by the folding scheme could not be created.
    #[error("Failed to create domain")]
    DomainCreationFailure,
    /// Reports that a polynomial division by the vanishing polynomial did not divide evenly.
    #[error("Indivisible by vanishing polynomial")]
    IndivisibleByVanishingPoly,
    /// Reports that a witness-instance pair failed the decider relation for this folding scheme.
    #[error("Unsatisfied relation: {0}")]
    UnsatisfiedRelation(String),
    /// Reports that public parameters are structurally invalid for the requested folding run.
    #[error("Invalid public parameters: {0}")]
    InvalidPublicParameters(String),
}
