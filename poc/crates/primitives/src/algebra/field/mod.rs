use ark_ff::{BigInteger, Fp, FpConfig, PrimeField};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::SynthesisError;
use ark_std::{
    any::TypeId,
    mem::transmute_copy,
    ops::{Add, Mul},
};

use crate::{
    algebra::{Val, field::emulated::EmulatedFieldVar},
    circuits::WitnessToPublic,
    traits::{ToEmulatedPublicInputs, ToPublicInputs},
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod emulated;

pub trait SonobeField:
    PrimeField<BasePrimeField = Self>
    + Absorbable
    + ToPublicInputs<Self>
    + Val<
        Var: FieldVar<Self, Self> + WitnessToPublic,
        EmulatedVar<Self> = EmulatedFieldVar<Self, Self>,
    >
{
    const BITS_PER_LIMB: usize;
}

impl<P: FpConfig<N>, const N: usize> SonobeField for Fp<P, N> {
    const BITS_PER_LIMB: usize = 32;
}

impl<P: FpConfig<N>, const N: usize> Val for Fp<P, N> {
    type PreferredConstraintField = Self;
    type Var = FpVar<Self>;

    type EmulatedVar<F: SonobeField> = EmulatedFieldVar<F, Self>;
}

impl<P: FpConfig<N>, const N: usize> Absorbable for Fp<P, N> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        if TypeId::of::<F>() == TypeId::of::<Self>() {
            dest.push(unsafe { transmute_copy::<Self, F>(self) });
        } else {
            let bits_per_limb = F::MODULUS_BIT_SIZE - 1;
            let num_limbs = Self::MODULUS_BIT_SIZE.div_ceil(bits_per_limb);

            let mut limbs = self
                .into_bigint()
                .to_bits_le()
                .chunks(bits_per_limb as usize)
                .map(|chunk| F::from(F::BigInt::from_bits_le(chunk)))
                .collect::<Vec<F>>();
            limbs.resize(num_limbs as usize, F::zero());

            dest.extend(&limbs)
        }
    }
}

impl<F: PrimeField> AbsorbableVar<F> for FpVar<F> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        dest.push(self.clone());
        Ok(())
    }
}

impl<P: FpConfig<N>, const N: usize> ToPublicInputs<Self> for Fp<P, N> {
    fn to_public_inputs(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl<F: SonobeField, P: SonobeField> ToEmulatedPublicInputs<F> for P {
    fn to_emulated_public_inputs(&self) -> Vec<F> {
        self.into_bigint()
            .to_bits_le()
            .chunks(F::BITS_PER_LIMB)
            .map(|chunk| F::from(F::BigInt::from_bits_le(chunk)))
            .collect()
    }
}

impl<F: PrimeField> WitnessToPublic for FpVar<F> {
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        self.enforce_equal(&FpVar::new_input(self.cs(), || self.value())?)
    }
}

pub trait TwoStageFieldVar:
    Clone
    + Add<Output = Self::Intermediate>
    + for<'a> Add<&'a Self, Output = Self::Intermediate>
    + Mul<Output = Self::Intermediate>
    + for<'a> Mul<&'a Self, Output = Self::Intermediate>
{
    type Intermediate: Clone
        + From<Self>
        + TryInto<Self>
        + Add<Output = Self::Intermediate>
        + for<'a> Add<&'a Self::Intermediate, Output = Self::Intermediate>
        + Mul<Output = Self::Intermediate>
        + for<'a> Mul<&'a Self::Intermediate, Output = Self::Intermediate>
        + Add<Self, Output = Self::Intermediate>
        + for<'a> Add<&'a Self, Output = Self::Intermediate>
        + Mul<Self, Output = Self::Intermediate>
        + for<'a> Mul<&'a Self, Output = Self::Intermediate>;
}

impl<F: PrimeField> TwoStageFieldVar for FpVar<F> {
    type Intermediate = Self;
}
