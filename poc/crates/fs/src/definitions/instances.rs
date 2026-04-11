use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    ops::{Deref, DerefMut},
    slice::Iter,
    vec::IntoIter,
};
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator},
    slice::Iter as RayonIter,
    vec::IntoIter as RayonIntoIter,
};
use sonobe_primitives::{
    arithmetizations::ArithConfig,
    commitments::{CommitmentDef, CommitmentDefGadget},
    traits::Dummy,
    transcripts::{Absorbable, AbsorbableVar},
};

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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlainInstance<V>(Vec<V>);

impl<V> Deref for PlainInstance<V> {
    type Target = Vec<V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V> DerefMut for PlainInstance<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<V> From<Vec<V>> for PlainInstance<V> {
    fn from(values: Vec<V>) -> Self {
        Self(values)
    }
}

impl<V> IntoIterator for PlainInstance<V> {
    type Item = V;
    type IntoIter = IntoIter<V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, V> IntoIterator for &'a PlainInstance<V> {
    type Item = &'a V;
    type IntoIter = Iter<'a, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<V: Send> IntoParallelIterator for PlainInstance<V> {
    type Item = V;
    type Iter = RayonIntoIter<V>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.into_par_iter()
    }
}

impl<'a, V: Sync> IntoParallelIterator for &'a PlainInstance<V> {
    type Item = &'a V;
    type Iter = RayonIter<'a, V>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.par_iter()
    }
}

impl<V> From<PlainInstance<V>> for Vec<V> {
    fn from(value: PlainInstance<V>) -> Self {
        value.0
    }
}

impl<V: Absorbable> Absorbable for PlainInstance<V> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest)
    }
}

impl<F: PrimeField, V: AbsorbableVar<F>> AbsorbableVar<F> for PlainInstance<V> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)
    }
}

impl<F: Field, X: AllocVar<Y, F>, Y> AllocVar<PlainInstance<Y>, F> for PlainInstance<X> {
    fn new_variable<T: Borrow<PlainInstance<Y>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let value = f()?;
        Vec::new_variable(cs, || Ok(&value.borrow()[..]), mode).map(Self)
    }
}

impl<F: PrimeField, X: CondSelectGadget<F>> CondSelectGadget<F> for PlainInstance<X> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.len() != false_value.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        true_value
            .iter()
            .zip(false_value.iter())
            .map(|(left, right)| cond.select(left, right))
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl<F: Field, V: GR1CSVar<F>> GR1CSVar<F> for PlainInstance<V> {
    type Value = PlainInstance<V::Value>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value().map(PlainInstance)
    }
}

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

#[cfg(test)]
mod tests {
    use core::any::type_name;

    use super::PlainInstance;

    #[test]
    fn plain_instance_has_a_domain_named_type_surface() {
        let name = type_name::<PlainInstance<u8>>();
        assert!(name.contains("PlainInstance"));
        assert!(!name.contains("TaggedVec"));
    }
}
