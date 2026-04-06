use ark_relations::gr1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, log2};
use thiserror::Error;

use crate::relations::{Relation, RelationGadget};

pub mod ccs;
pub mod r1cs;

#[derive(Error, Debug)]
pub enum Error {
    #[error("The provided assignments have incorrect shape: {0}")]
    MalformedAssignments(String),
    #[error("The provided assignments do not satisfy the constraint system: {0}")]
    UnsatisfiedAssignments(String),
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
}

pub trait ArithConfig: Clone + Debug + Default + PartialEq {
    fn degree(&self) -> usize;

    fn n_constraints(&self) -> usize;

    fn log_constraints(&self) -> usize {
        log2(self.n_constraints()) as usize
    }

    fn n_variables(&self) -> usize;

    fn n_public_inputs(&self) -> usize;

    fn n_witnesses(&self) -> usize;
}

pub trait Arith: Clone + Default + Send + Sync + CanonicalSerialize + CanonicalDeserialize {
    type Config: ArithConfig;

    fn config(&self) -> &Self::Config;

    fn config_mut(&mut self) -> &mut Self::Config;
}

pub trait ArithRelation<W: ?Sized, U: ?Sized>: Arith {
    type Evaluation;

    fn eval_relation(&self, w: &W, u: &U) -> Result<Self::Evaluation, Error>;

    fn check_evaluation(w: &W, u: &U, v: Self::Evaluation) -> Result<(), Error>;
}

impl<W, U, A: ArithRelation<W, U>> Relation<W, U> for A {
    type Error = Error;

    fn check_relation(&self, w: &W, u: &U) -> Result<(), Self::Error> {
        let e = self.eval_relation(w, u)?;
        Self::check_evaluation(w, u, e)
    }
}

pub trait ArithRelationGadget<WVar, UVar> {
    type Evaluation;

    fn eval_relation(&self, w: &WVar, u: &UVar) -> Result<Self::Evaluation, SynthesisError>;

    fn check_evaluation(w: &WVar, u: &UVar, e: Self::Evaluation) -> Result<(), SynthesisError>;
}

impl<WVar, UVar, A: ArithRelationGadget<WVar, UVar>> RelationGadget<WVar, UVar> for A {
    fn check_relation(&self, w: &WVar, u: &UVar) -> Result<(), SynthesisError> {
        let e = self.eval_relation(w, u)?;
        Self::check_evaluation(w, u, e)
    }
}
