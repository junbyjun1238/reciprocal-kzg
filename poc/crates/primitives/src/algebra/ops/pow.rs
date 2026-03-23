//! This module defines and implements powering utilities in and out of circuit.

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};

/// [`Pow`] provides powering operations for field elements.
pub trait Pow: Sized {
    /// [`Pow::powers`] computes:
    /// $self^0, self^1, ..., self^{n-1}$.
    fn powers(&self, n: usize) -> Vec<Self>;

    /// [`Pow::repeated_squares`] computes:
    /// $self^{2^0}, self^{2^1}, ..., self^{2^{n-1}}$.
    fn repeated_squares(&self, n: usize) -> Vec<Self>;

    /// [`Pow::powers_from_repeated_squares`] expands a vector of repeated
    /// squares $x^{2^0}, x^{2^1}, ..., x^{2^{n-1}}$ into all powers:
    /// $x^0, x^1, ..., x^{2^n - 1}$.
    fn powers_from_repeated_squares(squares: &[Self]) -> Vec<Self>;
}

impl<F: Field> Pow for F {
    fn powers(&self, n: usize) -> Vec<Self> {
        let mut res = vec![F::one(); n];
        for i in 1..n {
            res[i] = res[i - 1] * self;
        }
        res
    }

    fn repeated_squares(&self, n: usize) -> Vec<F> {
        if n == 0 {
            return vec![];
        }
        let mut res = vec![F::zero(); n];
        res[0] = *self;
        for i in 1..n {
            res[i] = res[i - 1].square();
        }
        res
    }

    fn powers_from_repeated_squares(squares: &[Self]) -> Vec<Self> {
        let mut pows = vec![F::one()];
        for square in squares.iter().rev() {
            pows = pows.into_iter().flat_map(|e| [e, e * square]).collect();
        }
        pows
    }
}

/// [`PowGadget`] is the in-circuit counterpart of [`Pow`], providing powering
/// operations for field element variables.
pub trait PowGadget: Sized {
    /// [`PowGadget::powers`] computes:
    /// $self^0, self^1, ..., self^{n-1}$.
    fn powers(&self, n: usize) -> Vec<Self>;

    /// [`PowGadget::repeated_squares`] computes:
    /// $self^{2^0}, self^{2^1}, ..., self^{2^{n-1}}$.
    fn repeated_squares(&self, n: usize) -> Vec<Self>;

    /// [`PowGadget::powers_from_repeated_squares`] expands a vector of repeated
    /// squares $x^{2^0}, x^{2^1}, ..., x^{2^{n-1}}$ into all powers:
    /// $x^0, x^1, ..., x^{2^n - 1}$.
    fn powers_from_repeated_squares(squares: &[Self]) -> Vec<Self>;
}

impl<F: PrimeField> PowGadget for FpVar<F> {
    fn powers(&self, n: usize) -> Vec<Self> {
        let mut res = vec![FpVar::one(); n];
        for i in 1..n {
            res[i] = &res[i - 1] * self;
        }
        res
    }

    fn repeated_squares(&self, n: usize) -> Vec<Self> {
        if n == 0 {
            return vec![];
        }
        let mut res = vec![FpVar::zero(); n];
        res[0] = self.clone();
        for i in 1..n {
            res[i] = &res[i - 1] * &res[i - 1];
        }
        res
    }

    fn powers_from_repeated_squares(squares: &[Self]) -> Vec<Self> {
        let mut pows = vec![FpVar::one()];
        for square in squares.iter().rev() {
            pows = pows
                .into_iter()
                .flat_map(|e| [e.clone(), e * square])
                .collect();
        }
        pows
    }
}
