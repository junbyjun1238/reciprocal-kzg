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
    ops::{Deref, DerefMut},
    slice::Iter,
    vec::IntoIter,
};
use rayon::{
    iter::{IntoParallelIterator, IntoParallelRefIterator},
    slice::Iter as RayonIter,
    vec::IntoIter as RayonIntoIter,
};
use sonobe_primitives::transcripts::{Absorbable, AbsorbableVar};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaggedVec<V, const TAG: char>(pub Vec<V>);

impl<V, const TAG: char> Deref for TaggedVec<V, TAG> {
    type Target = Vec<V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V, const TAG: char> DerefMut for TaggedVec<V, TAG> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<V, const TAG: char> From<Vec<V>> for TaggedVec<V, TAG> {
    fn from(v: Vec<V>) -> Self {
        Self(v)
    }
}

impl<V, const TAG: char> IntoIterator for TaggedVec<V, TAG> {
    type Item = V;
    type IntoIter = IntoIter<V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, V, const TAG: char> IntoIterator for &'a TaggedVec<V, TAG> {
    type Item = &'a V;
    type IntoIter = Iter<'a, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<V: Send, const TAG: char> IntoParallelIterator for TaggedVec<V, TAG> {
    type Item = V;

    type Iter = RayonIntoIter<V>;

    fn into_par_iter(self) -> Self::Iter {
        self.0.into_par_iter()
    }
}

impl<'a, V: Sync, const TAG: char> IntoParallelIterator for &'a TaggedVec<V, TAG> {
    type Iter = RayonIter<'a, V>;

    type Item = &'a V;

    fn into_par_iter(self) -> Self::Iter {
        self.0.par_iter()
    }
}

impl<V, const TAG: char> From<TaggedVec<V, TAG>> for Vec<V> {
    fn from(val: TaggedVec<V, TAG>) -> Self {
        val.0
    }
}

impl<V: Absorbable, const TAG: char> Absorbable for TaggedVec<V, TAG> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest)
    }
}

impl<F: PrimeField, V: AbsorbableVar<F>, const TAG: char> AbsorbableVar<F> for TaggedVec<V, TAG> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)
    }
}

impl<F: Field, X: AllocVar<Y, F>, Y, const TAG: char> AllocVar<TaggedVec<Y, TAG>, F>
    for TaggedVec<X, TAG>
{
    fn new_variable<T: Borrow<TaggedVec<Y, TAG>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let v = f()?;
        Vec::new_variable(cs, || Ok(&v.borrow()[..]), mode).map(Self)
    }
}

impl<F: PrimeField, X: CondSelectGadget<F>, const TAG: char> CondSelectGadget<F>
    for TaggedVec<X, TAG>
{
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
            .map(|(t, f)| cond.select(t, f))
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl<F: Field, V: GR1CSVar<F>, const TAG: char> GR1CSVar<F> for TaggedVec<V, TAG> {
    type Value = TaggedVec<V::Value, TAG>;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value().map(TaggedVec)
    }
}
