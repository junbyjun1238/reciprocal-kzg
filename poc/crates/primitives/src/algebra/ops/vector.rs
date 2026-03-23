//! This module provides definitions and implementations of in-circuit vector
//! operations.

use ark_relations::gr1cs::SynthesisError;
use ark_std::ops::{Add, Mul, Sub};

/// [`VectorGadget`] defines operations on in-circuit vector variables.
pub trait VectorGadget<FV> {
    /// [`VectorGadget::add`] computes the element-wise sum of two vectors.
    fn add(&self, other: &Self) -> Result<Vec<FV>, SynthesisError>;

    /// [`VectorGadget::sub`] computes the element-wise difference of two
    /// vectors.
    fn sub(&self, other: &Self) -> Result<Vec<FV>, SynthesisError>;

    /// [`VectorGadget::scale`] multiplies every element by a scalar.
    fn scale<Scalar, Output>(&self, scalar: &Scalar) -> Result<Vec<Output>, SynthesisError>
    where
        for<'a> &'a Scalar: Mul<&'a FV, Output = Output>;

    /// [`VectorGadget::hadamard`] computes the element-wise (Hadamard) product
    /// of two vectors.
    fn hadamard(&self, other: &Self) -> Result<Vec<FV>, SynthesisError>;
}

impl<FV> VectorGadget<FV> for [FV]
where
    for<'a> &'a FV: Add<&'a FV, Output = FV> + Sub<&'a FV, Output = FV> + Mul<&'a FV, Output = FV>,
{
    fn add(&self, other: &Self) -> Result<Vec<FV>, SynthesisError> {
        if self.len() != other.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(self.iter().zip(other.iter()).map(|(a, b)| a + b).collect())
    }

    fn sub(&self, other: &Self) -> Result<Vec<FV>, SynthesisError> {
        if self.len() != other.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(self.iter().zip(other.iter()).map(|(a, b)| a - b).collect())
    }

    fn scale<Scalar, Output>(&self, scalar: &Scalar) -> Result<Vec<Output>, SynthesisError>
    where
        for<'a> &'a Scalar: Mul<&'a FV, Output = Output>,
    {
        Ok(self.iter().map(|a| scalar * a).collect())
    }

    fn hadamard(&self, other: &Self) -> Result<Vec<FV>, SynthesisError> {
        if self.len() != other.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(self.iter().zip(other.iter()).map(|(a, b)| a * b).collect())
    }
}
