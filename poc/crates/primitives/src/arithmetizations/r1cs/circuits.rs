use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::gr1cs::{Namespace, SynthesisError};
use ark_std::{One, borrow::Borrow, ops::Mul};

use super::R1CS;
use crate::{
    algebra::ops::{
        eq::EquivalenceGadget,
        matrix::{MatrixGadget, SparseMatrixVar},
        vector::VectorGadget,
    },
    arithmetizations::ArithRelationGadget,
    circuits::Assignments,
};

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct R1CSMatricesVar<FVar> {
    A: SparseMatrixVar<FVar>,
    B: SparseMatrixVar<FVar>,
    C: SparseMatrixVar<FVar>,
}

impl<F: PrimeField, ConstraintF: PrimeField, FVar: AllocVar<F, ConstraintF>>
    AllocVar<R1CS<F>, ConstraintF> for R1CSMatricesVar<FVar>
{
    fn new_variable<T: Borrow<R1CS<F>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let val = val.borrow();

            Ok(Self {
                A: SparseMatrixVar::<FVar>::new_variable(cs.clone(), || Ok(&val.A), mode)?,
                B: SparseMatrixVar::<FVar>::new_variable(cs.clone(), || Ok(&val.B), mode)?,
                C: SparseMatrixVar::<FVar>::new_variable(cs.clone(), || Ok(&val.C), mode)?,
            })
        })
    }
}

impl<FVar> R1CSMatricesVar<FVar>
where
    SparseMatrixVar<FVar>: MatrixGadget<FVar>,
    [FVar]: VectorGadget<FVar>,
    for<'a> &'a FVar: Mul<&'a FVar, Output = FVar>,
{
    #[allow(non_snake_case)]
    pub fn evaluate_at(
        &self,
        z: Assignments<FVar, impl AsRef<[FVar]>>,
    ) -> Result<Vec<FVar>, SynthesisError> {
        let Az = self.A.mul_vector(&z)?;
        let Bz = self.B.mul_vector(&z)?;
        let Cz = self.C.mul_vector(&z)?;
        let uCz = Cz.scale(&z[0])?;
        let AzBz = Az.hadamard(&Bz)?;
        AzBz.sub(&uCz)
    }
}

impl<FVar, WVar: AsRef<[FVar]>, UVar: AsRef<[FVar]>> ArithRelationGadget<WVar, UVar>
    for R1CSMatricesVar<FVar>
where
    SparseMatrixVar<FVar>: MatrixGadget<FVar>,
    [FVar]: VectorGadget<FVar> + EquivalenceGadget<[FVar]>,
    FVar: Clone + Zero + One,
    for<'a> &'a FVar: Mul<&'a FVar, Output = FVar>,
{
    type Evaluation = Vec<FVar>;

    fn eval_relation(&self, w: &WVar, u: &UVar) -> Result<Self::Evaluation, SynthesisError> {
        self.evaluate_at((FVar::one(), u.as_ref(), w.as_ref()).into())
    }

    fn check_evaluation(_w: &WVar, _u: &UVar, e: Self::Evaluation) -> Result<(), SynthesisError> {
        e.enforce_equivalent(&vec![FVar::zero(); e.len()])
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::{error::Error, rand::thread_rng};

    use super::*;
    use crate::{
        circuits::utils::{constraints_for_test, satisfying_assignments_for_test},
        relations::Relation,
    };

    #[test]
    fn test_eval() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let r1cs = constraints_for_test::<Fr>();

        assert!(
            r1cs.evaluate_at(satisfying_assignments_for_test(Fr::rand(&mut rng)))?
                .into_iter()
                .all(|e| e.is_zero())
        );
        assert!(
            !r1cs
                .evaluate_at(Assignments::from((
                    Fr::one(),
                    vec![Fr::rand(&mut rng)],
                    vec![
                        Fr::rand(&mut rng),
                        Fr::rand(&mut rng),
                        Fr::rand(&mut rng),
                        Fr::rand(&mut rng),
                    ],
                )))?
                .into_iter()
                .all(|e| e.is_zero())
        );

        Ok(())
    }

    #[test]
    fn test_check() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let r1cs = constraints_for_test::<Fr>();

        let assignments = satisfying_assignments_for_test(Fr::rand(&mut rng));

        assert!(
            r1cs.check_relation(&assignments.private, &assignments.public)
                .is_ok()
        );
        assert!(
            r1cs.check_relation(
                &[
                    Fr::rand(&mut rng),
                    Fr::rand(&mut rng),
                    Fr::rand(&mut rng),
                    Fr::rand(&mut rng),
                ],
                &[Fr::rand(&mut rng)]
            )
            .is_err()
        );

        Ok(())
    }
}
