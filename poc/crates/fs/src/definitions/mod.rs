pub mod algorithms;
pub mod circuits;
pub mod errors;
pub mod instances;
pub mod keys;
pub mod utils;
pub mod variants;
pub mod witnesses;

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};
use sonobe_primitives::{
    arithmetizations::Arith,
    circuits::AssignmentsOwned,
    commitments::{CommitmentDef, CommitmentDefGadget},
    relations::{Relation, WitnessInstanceSampler},
    traits::{Dummy, SonobeField},
};

use self::{
    errors::Error,
    instances::{FoldingInstance, FoldingInstanceVar},
    keys::DeciderKey,
    witnesses::FoldingWitness,
};

pub trait FoldingSchemeDef {
    type CM: CommitmentDef<Scalar: SonobeField>;
    type RW: FoldingWitness<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type RU: FoldingInstance<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type IW: FoldingWitness<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type IU: FoldingInstance<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    type TranscriptField: SonobeField;
    type Arith: Arith<Config = <Self::DeciderKey as DeciderKey>::ArithConfig>;
    type Config;
    type PublicParam;
    type DeciderKey: DeciderKey
        + Clone
        + Relation<Self::RW, Self::RU, Error = Error>
        + Relation<Self::IW, Self::IU, Error = Error>
        + WitnessInstanceSampler<Self::RW, Self::RU, Source = (), Error = Error>
        + WitnessInstanceSampler<
            Self::IW,
            Self::IU,
            Source = AssignmentsOwned<<Self::CM as CommitmentDef>::Scalar>,
            Error = Error,
        >;
    type Challenge;
    type Proof<const M: usize, const N: usize>: Clone
        + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
}

pub trait FoldingSchemeDefGadget {
    type Widget: FoldingSchemeDef;

    type CM: CommitmentDefGadget<Widget = <Self::Widget as FoldingSchemeDef>::CM>;
    type RU: FoldingInstanceVar<Self::CM, Value = <Self::Widget as FoldingSchemeDef>::RU>;
    type IU: FoldingInstanceVar<Self::CM, Value = <Self::Widget as FoldingSchemeDef>::IU>;

    type VerifierKey;

    type Challenge: AllocVar<
            <Self::Widget as FoldingSchemeDef>::Challenge,
            <Self::CM as CommitmentDefGadget>::ConstraintField,
        > + GR1CSVar<
            <Self::CM as CommitmentDefGadget>::ConstraintField,
            Value = <Self::Widget as FoldingSchemeDef>::Challenge,
        >;
    type Proof<const M: usize, const N: usize>: AllocVar<
            <Self::Widget as FoldingSchemeDef>::Proof<M, N>,
            <Self::CM as CommitmentDefGadget>::ConstraintField,
        > + GR1CSVar<
            <Self::CM as CommitmentDefGadget>::ConstraintField,
            Value = <Self::Widget as FoldingSchemeDef>::Proof<M, N>,
        >;
}
