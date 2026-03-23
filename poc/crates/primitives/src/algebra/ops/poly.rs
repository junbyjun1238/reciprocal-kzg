//! This module provides helpers for working with polynomials inside circuits.

use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{DenseMultilinearExtension, EvaluationDomain, GeneralEvaluationDomain};
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::gr1cs::SynthesisError;
use ark_std::log2;

use super::pow::Pow;

/// [`MLEHelper`] provides functionality for multilinear extensions.
pub trait MLEHelper<F> {
    /// [`MLEHelper::from_evaluations`] builds a multilinear extension from a
    /// (possibly non-power-of-two) vector of evaluations, padding with zeros
    /// up to the next power of two.
    fn from_evaluations(evaluations: &[F]) -> Self;
}

impl<F: Field> MLEHelper<F> for DenseMultilinearExtension<F> {
    fn from_evaluations(evaluations: &[F]) -> Self {
        let l = evaluations.len();
        let pad = vec![Zero::zero(); l.next_power_of_two() - l];
        Self::from_evaluations_vec(log2(l) as usize, [evaluations, &pad].concat())
    }
}

/// [`EvaluationDomainGadget`] provides a subset of evaluation domain operations
/// in [`EvaluationDomain`] for in-circuit field variables.
pub trait EvaluationDomainGadget<F: PrimeField> {
    /// [`EvaluationDomainGadget::evaluate_all_lagrange_coefficients_var`]
    /// computes all Lagrange basis polynomials evaluated at `tau`.
    ///
    /// It is the in-circuit counterpart of [`EvaluationDomain::evaluate_all_lagrange_coefficients`].
    fn evaluate_all_lagrange_coefficients_var(
        &self,
        tau: &FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;

    /// [`EvaluationDomainGadget::evaluate_vanishing_polynomial_var`] evaluates
    /// the vanishing polynomial of the domain at `tau`.
    ///
    /// It is the in-circuit counterpart of [`EvaluationDomain::evaluate_vanishing_polynomial`].
    fn evaluate_vanishing_polynomial_var(&self, tau: &FpVar<F>)
    -> Result<FpVar<F>, SynthesisError>;
}

impl<F: PrimeField> EvaluationDomainGadget<F> for GeneralEvaluationDomain<F> {
    fn evaluate_all_lagrange_coefficients_var(
        &self,
        tau: &FpVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let size = self.size() as u64;
        let size_inv = self.size_inv();
        let offset = self.coset_offset();
        let offset_inv = self.coset_offset_inv();
        let group_gen = self.group_gen();

        // We assume that the evaluation of vanishing polynomial at tau is non-0

        let l_i = (tau.pow_by_constant([size])? * offset_inv.pow([size - 1]) - offset) * size_inv;

        group_gen
            .powers(size as usize)
            .into_iter()
            .map(|g| (&l_i * g).mul_by_inverse(&(tau - offset * g)))
            .collect()
    }

    fn evaluate_vanishing_polynomial_var(
        &self,
        tau: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        Ok(tau.pow_by_constant([self.size() as u64])? - self.coset_offset_pow_size())
    }
}
