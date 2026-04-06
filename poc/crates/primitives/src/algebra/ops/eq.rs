use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

pub trait EquivalenceGadget<Other: ?Sized> {
    fn enforce_equivalent(&self, other: &Other) -> Result<(), SynthesisError>;
}

impl<F: PrimeField> EquivalenceGadget<FpVar<F>> for FpVar<F> {
    fn enforce_equivalent(&self, other: &FpVar<F>) -> Result<(), SynthesisError> {
        self.enforce_equal(other)
    }
}

impl<T: EquivalenceGadget<T>> EquivalenceGadget<[T]> for [T] {
    fn enforce_equivalent(&self, other: &[T]) -> Result<(), SynthesisError> {
        self.iter()
            .zip(other)
            .try_for_each(|(a, b)| a.enforce_equivalent(b))
    }
}
