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

/// Host-side contract for folding instances that carry commitments and public inputs.
pub trait FoldingInstance<CM: CommitmentDef>: Clone + Debug + PartialEq + Eq + Absorbable {
    /// The number of commitments returned by [`Self::commitments`].
    const N_COMMITMENTS: usize;

    /// Returns the commitments that identify this instance inside the folding protocol.
    fn commitments(&self) -> Vec<&CM::Commitment>;

    /// Returns the scalar public inputs carried by this instance.
    fn public_inputs(&self) -> &[CM::Scalar];

    /// Returns mutable access to the scalar public inputs carried by this instance.
    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar];
}

/// Commitment-free folding instance used for plain scalar input vectors.
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

/// In-circuit contract for folding instances that mirror a host-side [`FoldingInstance`].
pub trait FoldingInstanceVar<CM: CommitmentDefGadget>:
    AllocVar<Self::Value, CM::ConstraintField>
    + GR1CSVar<CM::ConstraintField, Value: FoldingInstance<CM::Widget>>
    + AbsorbableVar<CM::ConstraintField>
    + CondSelectGadget<CM::ConstraintField>
{
    /// Returns the commitment variables that identify this instance in-circuit.
    fn commitments(&self) -> Vec<&CM::CommitmentVar>;

    /// Returns the scalar public inputs exposed by this in-circuit instance.
    fn public_inputs(&self) -> &[CM::ScalarVar];

    /// Allocates an instance witness by reusing the non-public parts of `instance`
    /// and replacing only its public inputs with `public_inputs`.
    fn new_witness_with_public_inputs(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        instance: &Self::Value,
        public_inputs: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError>;
}

impl<CM: CommitmentDefGadget> FoldingInstanceVar<CM> for PlainInstanceVar<CM::ScalarVar> {
    fn commitments(&self) -> Vec<&CM::CommitmentVar> {
        vec![]
    }

    fn public_inputs(&self) -> &[CM::ScalarVar] {
        self
    }

    fn new_witness_with_public_inputs(
        _cs: impl Into<Namespace<CM::ConstraintField>>,
        _instance: &Self::Value,
        public_inputs: Vec<CM::ScalarVar>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self(public_inputs))
    }
}

/// In-circuit counterpart of [`PlainInstance`].
pub type PlainInstanceVar<V> = PlainInstance<V>;
