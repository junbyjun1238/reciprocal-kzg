use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;
use ark_relations::gr1cs::{ConstraintSystem, Matrix};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, cfg_into_iter, cfg_iter, fmt::Debug, marker::PhantomData};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{Arith, ArithRelation, Error, r1cs::R1CS};
use crate::{
    algebra::ops::poly::MLEHelper,
    arithmetizations::{ArithConfig, r1cs::R1CSConfig},
    circuits::Assignments,
};

pub mod circuits;

pub trait CCSVariant: Clone + Debug + PartialEq + Default + Sync + Send {
    fn n_matrices() -> usize;

    fn degree() -> usize;

    fn multisets_vec() -> Vec<Vec<usize>>;

    fn coefficients_vec<F: Field>() -> Vec<F>;
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCSConfig<V: CCSVariant> {
    _v: PhantomData<V>,
    m: usize,
    n: usize,
    l: usize,
}

impl<V: CCSVariant> ArithConfig for CCSConfig<V> {
    #[inline]
    fn degree(&self) -> usize {
        V::degree()
    }

    #[inline]
    fn n_constraints(&self) -> usize {
        self.m
    }

    #[inline]
    fn n_variables(&self) -> usize {
        self.n
    }

    #[inline]
    fn n_public_inputs(&self) -> usize {
        self.l
    }

    #[inline]
    fn n_witnesses(&self) -> usize {
        self.n_variables() - self.n_public_inputs() - 1
    }
}

impl<Cfg: Borrow<R1CSConfig>, V: CCSVariant> From<Cfg> for CCSConfig<V> {
    fn from(cfg: Cfg) -> Self {
        let cfg = cfg.borrow();
        Self {
            _v: PhantomData,
            m: cfg.n_constraints(),
            n: cfg.n_variables(),
            l: cfg.n_public_inputs(),
        }
    }
}

impl<F: Field, V: CCSVariant> From<&ConstraintSystem<F>> for CCSConfig<V> {
    fn from(cs: &ConstraintSystem<F>) -> Self {
        R1CSConfig::from(cs).into()
    }
}

#[allow(non_snake_case)]
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CCS<F: Field, V: CCSVariant> {
    cfg: CCSConfig<V>,

    pub(super) M: Vec<Matrix<F>>,
}

impl<F: Field, V: CCSVariant> CCS<F, V> {
    pub fn evaluate_at(&self, z: Assignments<F, impl AsRef<[F]> + Sync>) -> Result<Vec<F>, Error> {
        let cfg = &self.cfg;

        let public_len = z.public.as_ref().len();
        let private_len = z.private.as_ref().len();
        if public_len != cfg.n_public_inputs() {
            return Err(Error::MalformedAssignments(format!(
                "The number of public inputs in R1CS ({}) does not match the length of the provided public inputs ({}).",
                cfg.n_public_inputs(),
                public_len
            )));
        }
        if private_len != cfg.n_witnesses() {
            return Err(Error::MalformedAssignments(format!(
                "The number of witnesses in R1CS ({}) does not match the length of the provided witnesses ({}).",
                cfg.n_witnesses(),
                private_len
            )));
        }

        Ok(cfg_into_iter!(0..cfg.n_constraints())
            .map(|row| {
                V::multisets_vec()
                    .into_iter()
                    .zip(V::coefficients_vec::<F>())
                    .map(|(s, c)| {
                        c * s
                            .iter()
                            .map(|&i| {
                                self.M[i][row]
                                    .iter()
                                    .map(|(val, col)| z[*col] * val)
                                    .sum::<F>()
                            })
                            .product::<F>()
                    })
                    .sum()
            })
            .collect())
    }

    pub fn mles(
        &self,
        z: Assignments<F, impl AsRef<[F]> + Sync>,
    ) -> Vec<DenseMultilinearExtension<F>> {
        (0..V::n_matrices())
            .map(|i| {
                DenseMultilinearExtension::from_evaluations(
                    &cfg_iter!(self.M[i])
                        .map(|row| row.iter().map(|(val, col)| z[*col] * val).sum())
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }
}

impl<F: Field, V: CCSVariant> Default for CCS<F, V> {
    #[inline]
    fn default() -> Self {
        Self {
            cfg: CCSConfig::default(),
            M: vec![vec![]; V::n_matrices()],
        }
    }
}

impl<F: Field, V: CCSVariant> Arith for CCS<F, V> {
    type Config = CCSConfig<V>;

    #[inline]
    fn config(&self) -> &Self::Config {
        &self.cfg
    }

    #[inline]
    fn config_mut(&mut self) -> &mut Self::Config {
        &mut self.cfg
    }
}

impl<F: Field, W: AsRef<[F]>, U: AsRef<[F]>, V: CCSVariant> ArithRelation<W, U> for CCS<F, V> {
    type Evaluation = Vec<F>;

    fn eval_relation(&self, w: &W, u: &U) -> Result<Self::Evaluation, Error> {
        self.evaluate_at((F::one(), u.as_ref(), w.as_ref()).into())
    }

    fn check_evaluation(_w: &W, _u: &U, e: Self::Evaluation) -> Result<(), Error> {
        cfg_into_iter!(e)
            .all(|i| i.is_zero())
            .then_some(())
            .ok_or(Error::UnsatisfiedAssignments(
                "Evaluation contains non-zero values".into(),
            ))
    }
}

impl<F: Field> From<R1CS<F>> for CCS<F, R1CSConfig> {
    fn from(r1cs: R1CS<F>) -> Self {
        Self {
            cfg: r1cs.config().into(),
            M: vec![r1cs.A, r1cs.B, r1cs.C],
        }
    }
}

impl<F: Field> From<&ConstraintSystem<F>> for CCS<F, R1CSConfig> {
    fn from(cs: &ConstraintSystem<F>) -> Self {
        R1CS::from(cs).into()
    }
}

impl<F: Field> From<ConstraintSystem<F>> for CCS<F, R1CSConfig> {
    fn from(cs: ConstraintSystem<F>) -> Self {
        Self::from(&cs)
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
        let ccs: CCS<Fr, R1CSConfig> = constraints_for_test::<Fr>().into();

        assert!(
            ccs.evaluate_at(satisfying_assignments_for_test(Fr::rand(&mut rng)))?
                .into_iter()
                .all(|e| e.is_zero())
        );
        assert!(
            !ccs.evaluate_at(Assignments::from((
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
        let ccs: CCS<Fr, R1CSConfig> = constraints_for_test::<Fr>().into();

        let assignments = satisfying_assignments_for_test(Fr::rand(&mut rng));

        assert!(
            ccs.check_relation(&assignments.private, &assignments.public)
                .is_ok()
        );
        assert!(
            ccs.check_relation(
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
