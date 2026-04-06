use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    arithmetizations::Error as ArithError, commitments::Error as CommitmentError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    ArithError(#[from] ArithError),
    #[error(transparent)]
    CommitmentError(#[from] CommitmentError),
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    #[error("Unsupported use case: {0}")]
    Unsupported(String),
    #[error("Failed to create domain")]
    DomainCreationFailure,
    #[error("Indivisible by vanishing polynomial")]
    IndivisibleByVanishingPoly,
    #[error("Unsatisfied relation: {0}")]
    UnsatisfiedRelation(String),
    #[error("Invalid public parameters: {0}")]
    InvalidPublicParameters(String),
}
