use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, select::CondSelectGadget};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::fmt::Debug;
use sonobe_primitives::{
    arithmetizations::ArithConfig,
    commitments::{CommitmentDef, CommitmentDefGadget},
    traits::Dummy,
    transcripts::{Absorbable, AbsorbableVar},
};

use super::utils::TaggedVec;

pub trait FoldingInstance<CM: CommitmentDef>: Clone + Debug + PartialEq + Eq + Absorbable {
    const N_COMMITMENTS: usize;

    fn commitments(&self) -> Vec<&CM::Commitment>;

    fn public_inputs(&self) -> &[CM::Scalar];

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar];
}

pub type PlainInstance<V> = TaggedVec<V, 'u'>;

impl<V: Default + Clone, A: ArithConfig> Dummy<&A> for PlainInstance<V> {
    fn dummy(cfg: &A) -> Self {
        vec![V::default(); cfg.n_public_inputs()].into()
    }
}

impl<CM: CommitmentDef> FoldingInstance<CM> for PlainInstance<CM::Scalar> {
    const N_COMMITMENTS: usize = 0;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        self
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        self
    }
}

pub trait FoldingInstanceVar<CM: CommitmentDefGadget>:
    AllocVar<Self::Value, CM::ConstraintField>
    + GR1CSVar<CM::ConstraintField, Value: FoldingInstance<CM::Widget>>
    + AbsorbableVar<CM::ConstraintField>
    + CondSelectGadget<CM::ConstraintField>
{
    fn commitments(&self) -> Vec<&CM::CommitmentVar>;

    fn public_inputs(&self) -> &Vec<CM::ScalarVar>;

    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        u: &Self::Value,
        x: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError>;
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for PlainInstanceVar<CM::ScalarVar> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![]
    }

    fn public_inputs(&self) -> &Vec<CM::ScalarVar> {
        self
    }

    fn new_witness_with_public_inputs(
        _cs: impl Into<Namespace<CM::ConstraintField>>,
        _u: &Self::Value,
        x: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self(x))
    }
}

pub type PlainInstanceVar<V> = PlainInstance<V>;
