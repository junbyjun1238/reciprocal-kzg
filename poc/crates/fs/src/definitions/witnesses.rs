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
    ops::Deref,
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

pub trait FoldingWitness<CM: CommitmentDef>: Debug {
    const N_OPENINGS: usize;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)>;
}

/// Commitment-free folding witness used for plain scalar witness vectors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlainWitness<V>(Vec<V>);

impl<V> Deref for PlainWitness<V> {
    type Target = [V];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl<V> AsRef<[V]> for PlainWitness<V> {
    fn as_ref(&self) -> &[V] {
        self.0.as_slice()
    }
}

impl<V> From<Vec<V>> for PlainWitness<V> {
    fn from(values: Vec<V>) -> Self {
        Self(values)
    }
}

impl<V> IntoIterator for PlainWitness<V> {
    type Item = V;
    type IntoIter = IntoIter<V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, V> IntoIterator for &'a PlainWitness<V> {
    type Item = &'a V;
    type IntoIter = Iter<'a, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<V: Send> IntoParallelIterator for PlainWitness<V> {
    type Item = V;
    type Iter = RayonIntoIter<V>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.into_par_iter()
    }
}

impl<'a, V: Sync> IntoParallelIterator for &'a PlainWitness<V> {
    type Item = &'a V;
    type Iter = RayonIter<'a, V>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.par_iter()
    }
}

impl<V: Absorbable> Absorbable for PlainWitness<V> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest)
    }
}

impl<F: PrimeField, V: AbsorbableVar<F>> AbsorbableVar<F> for PlainWitness<V> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)
    }
}

impl<F: Field, X: AllocVar<Y, F>, Y> AllocVar<PlainWitness<Y>, F> for PlainWitness<X> {
    fn new_variable<T: Borrow<PlainWitness<Y>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let value = f()?;
        Vec::new_variable(cs, || Ok(value.borrow().as_ref()), mode).map(Self)
    }
}

impl<F: PrimeField, X: CondSelectGadget<F>> CondSelectGadget<F> for PlainWitness<X> {
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

impl<F: Field, V: GR1CSVar<F>> GR1CSVar<F> for PlainWitness<V> {
    type Value = PlainWitness<V::Value>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value().map(PlainWitness)
    }
}

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

/// In-circuit counterpart of [`PlainWitness`].
pub type PlainWitnessVar<V> = PlainWitness<V>;

#[cfg(test)]
mod tests {
    use core::any::type_name;

    use super::PlainWitness;

    #[test]
    fn plain_witness_has_a_domain_named_type_surface() {
        let name = type_name::<PlainWitness<u8>>();
        assert!(name.contains("PlainWitness"));
        assert!(!name.contains("TaggedVec"));
    }
}
