//! This module defines and implements the computation of random linear
//! combination (RLC).
//!
//! An RLC computes $\sum v_i \cdot c_i$ where $v_i$ are values (scalars or
//! vectors) and $c_i$ are the randomness (challenge coefficients), which is
//! used extensively in folding schemes.

use ark_std::{
    iter::Sum,
    ops::{Add, Mul},
};

/// [`ScalarRLC`] computes the random linear combination for a sequence of
/// scalars (i.e., each $v_i$ is a scalar).
pub trait ScalarRLC<Coeff> {
    /// [`ScalarRLC::Value`] is the result type of the RLC computation.
    type Value;

    /// [`ScalarRLC::scalar_rlc`] evaluates the RLC with the given coefficients
    /// `coeffs`.
    fn scalar_rlc(self, coeffs: &[Coeff]) -> Self::Value;
}

impl<I: Iterator + Sized, Coeff> ScalarRLC<Coeff> for I
where
    I::Item: Add<Output = I::Item> + Sum + for<'a> Mul<&'a Coeff, Output = I::Item>,
{
    type Value = I::Item;

    fn scalar_rlc(self, coeffs: &[Coeff]) -> Self::Value {
        self.zip(coeffs).map(|(v, c)| v * c).sum::<I::Item>()
    }
}

/// [`SliceRLC`] computes the random linear combination for a sequence of
/// vectors (i.e., each $v_i$ is a vector), by computing the RLC element-wise.
// TODO (@winderica): can we unify `ScalarRLC` and `SliceRLC` into one trait?
pub trait SliceRLC<Coeff> {
    /// [`SliceRLC::Value`] is the result type of the RLC computation.
    type Value;

    /// [`SliceRLC::slice_rlc`] evaluates the RLC with the given coefficients
    /// `coeffs`.
    fn slice_rlc(self, coeffs: &[Coeff]) -> Vec<Self::Value>;
}

impl<'a, T, I: Iterator<Item = &'a [T]>, Coeff> SliceRLC<Coeff> for I
where
    T: 'a + Add<Output = T> + Clone,
    for<'x> T: Mul<&'x Coeff, Output = T>,
{
    type Value = T;

    fn slice_rlc(self, coeffs: &[Coeff]) -> Vec<Self::Value> {
        let mut iter = self
            .zip(coeffs)
            .map(|(v, c)| v.iter().map(|x| x.clone() * c));
        let first = iter.next().unwrap();

        iter.fold(first.collect(), |acc, v| {
            acc.into_iter().zip(v).map(|(a, b)| a + b).collect()
        })
    }
}
