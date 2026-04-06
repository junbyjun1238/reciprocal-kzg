use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};
use ark_std::fmt::Debug;
use sonobe_primitives::{
    arithmetizations::ArithConfig,
    commitments::{CommitmentDef, CommitmentDefGadget},
    traits::Dummy,
};

use super::utils::TaggedVec;

pub trait FoldingWitness<CM: CommitmentDef>: Debug {
    const N_OPENINGS: usize;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)>;
}

pub type PlainWitness<V> = TaggedVec<V, 'w'>;

impl<V: Default + Clone, A: ArithConfig> Dummy<&A> for PlainWitness<V> {
    fn dummy(cfg: &A) -> Self {
        vec![V::default(); cfg.n_witnesses()].into()
    }
}

impl<CM: CommitmentDef> FoldingWitness<CM> for PlainWitness<CM::Scalar> {
    const N_OPENINGS: usize = 0;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)> {
        vec![]
    }
}

pub trait FoldingWitnessVar<CM: CommitmentDefGadget>:
    AllocVar<Self::Value, CM::ConstraintField>
    + GR1CSVar<CM::ConstraintField, Value: FoldingWitness<CM::Widget>>
{
}

impl<CM: CommitmentDefGadget, T> FoldingWitnessVar<CM> for T where
    T: AllocVar<Self::Value, CM::ConstraintField>
        + GR1CSVar<CM::ConstraintField, Value: FoldingWitness<CM::Widget>>
{
}

pub type PlainWitnessVar<V> = PlainWitness<V>;
