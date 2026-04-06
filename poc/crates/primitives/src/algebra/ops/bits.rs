use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

use crate::{algebra::field::emulated::Bounds, utils::assignments::assignment_or_setup};

pub trait FromBits {
    fn from_bits_le(bits: &[bool]) -> Self;
}

impl<F: PrimeField> FromBits for F {
    fn from_bits_le(bits: &[bool]) -> Self {
        F::from(F::BigInt::from_bits_le(bits))
    }
}

pub trait FromBitsGadget<F: PrimeField>: Sized {
    fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self, SynthesisError>;

    fn from_bounded_bits_le(bits: &[Boolean<F>], bounds: Bounds) -> Result<Self, SynthesisError>;
}

pub trait ToBitsGadgetExt<F: PrimeField>: Sized {
    fn to_n_bits_le(&self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;

    fn enforce_bit_length(&self, n: usize) -> Result<(), SynthesisError> {
        self.to_n_bits_le(n)?;
        Ok(())
    }
}
impl<F: PrimeField> FromBitsGadget<F> for FpVar<F> {
    fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self, SynthesisError> {
        Boolean::le_bits_to_fp(bits)
    }

    fn from_bounded_bits_le(bits: &[Boolean<F>], _bounds: Bounds) -> Result<Self, SynthesisError> {
        Self::from_bits_le(bits)
    }
}

impl<F: PrimeField> ToBitsGadgetExt<F> for FpVar<F> {
    fn to_n_bits_le(&self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let bits = assignment_or_setup(
            self.cs(),
            || vec![false; n],
            || {
                let mut bits = self.value()?.into_bigint().to_bits_le();
                bits.resize(n, false);
                Ok(bits)
            },
        )?;
        let bits = Vec::new_variable_with_inferred_mode(self.cs(), || Ok(bits))?;

        Boolean::le_bits_to_fp(&bits)?.enforce_equal(self)?;

        Ok(bits)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::gr1cs::{ConstraintSystem, SynthesisMode};

    use super::ToBitsGadgetExt;

    #[test]
    fn to_n_bits_le_uses_setup_placeholder() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_mode(SynthesisMode::Setup);

        let value = FpVar::new_witness(
            cs.clone(),
            || -> Result<Fr, ark_relations::gr1cs::SynthesisError> {
                Err(ark_relations::gr1cs::SynthesisError::AssignmentMissing)
            },
        )
        .expect("setup mode should allow allocating an unassigned witness");
        let bits = value
            .to_n_bits_le(8)
            .expect("setup mode should use an explicit placeholder");

        assert_eq!(bits.len(), 8);
    }
}
