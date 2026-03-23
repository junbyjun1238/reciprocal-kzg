//! This module defines traits for conversion between bit representations and
//! algebraic types inside and outside circuits.

use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;

use crate::algebra::field::emulated::Bounds;

/// [`FromBits`] reconstructs a value from bits.
pub trait FromBits {
    /// [`FromBits::from_bits_le`] computes a value from its little-endian bits.
    fn from_bits_le(bits: &[bool]) -> Self;
}

impl<F: PrimeField> FromBits for F {
    fn from_bits_le(bits: &[bool]) -> Self {
        F::from(F::BigInt::from_bits_le(bits))
    }
}

/// [`FromBitsGadget`] is the in-circuit counterpart of [`FromBits`], which
/// reconstructs an in-circuit variable from boolean variables.
pub trait FromBitsGadget<F: PrimeField>: Sized {
    /// [`FromBitsGadget::from_bits_le`] computes a variable from its
    /// little-endian bits, inferring bounds from the length of `bits`.
    fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self, SynthesisError>;

    /// [`FromBitsGadget::from_bounded_bits_le`] computes a variable from its
    /// little-endian bits with explicitly supplied [`Bounds`].
    fn from_bounded_bits_le(bits: &[Boolean<F>], bounds: Bounds) -> Result<Self, SynthesisError>;
}

/// [`ToBitsGadgetExt`] extends the standard [`ark_r1cs_std::convert::ToBitsGadget`]
/// with more functionality.
pub trait ToBitsGadgetExt<F: PrimeField>: Sized {
    /// [`ToBitsGadgetExt::to_n_bits_le`] decomposes `self` into `n`
    /// little-endian bits.
    ///
    /// An error is returned if `self` cannot be represented in `n` bits.
    fn to_n_bits_le(&self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;

    /// [`ToBitsGadgetExt::enforce_bit_length`] enforces that `self` can be
    /// represented in at most `n` bits.
    ///
    /// This is useful for checking that a field element is within the range of
    /// `[0, 2^n - 1]`
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
        let mut bits = self.value().unwrap_or_default().into_bigint().to_bits_le();
        bits.resize(n, false);
        let bits = Vec::new_variable_with_inferred_mode(self.cs(), || Ok(bits))?;

        Boolean::le_bits_to_fp(&bits)?.enforce_equal(self)?;

        Ok(bits)
    }
}
