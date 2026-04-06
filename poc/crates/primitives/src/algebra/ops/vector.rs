use ark_relations::gr1cs::SynthesisError;
use ark_std::ops::{Add, Mul, Sub};

pub trait VectorGadget<FV> {
    fn add(&self, other: &Self) -> Result<Vec<FV>, SynthesisError>;

    fn sub(&self, other: &Self) -> Result<Vec<FV>, SynthesisError>;

    fn scale<Scalar, Output>(&self, scalar: &Scalar) -> Result<Vec<Output>, SynthesisError>
    where
        for<'a> &'a Scalar: Mul<&'a FV, Output = Output>;

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
