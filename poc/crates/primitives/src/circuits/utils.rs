use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    fields::fp::{AllocatedFp, FpVar},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};

use super::Assignments;
use crate::{
    arithmetizations::r1cs::{R1CS, R1CSConfig},
    circuits::FCircuit,
    traits::SonobeField,
};

pub struct CircuitForTest<F: PrimeField> {
    pub x: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CircuitForTest<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x = AllocatedFp::new_input(cs.clone(), || Ok(self.x))?;
        let y = AllocatedFp::new_witness(cs.clone(), || Ok(self.x.pow([3]) + self.x + F::from(5)))?;

        let x_square = x.square()?;
        let x_cube = x_square.mul(&x);
        let t = AllocatedFp::new_witness(cs.clone(), || Ok(self.x.pow([3]) + self.x))?;
        let x_cube_plus_x = x.add(&x_cube);
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x.variable.into(),
            || Variable::one().into(),
            || t.variable.into(),
        )?;
        let x_cube_plus_x_plus_5 = t.add_constant(F::from(5));
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x_plus_5.variable.into(),
            || Variable::one().into(),
            || y.variable.into(),
        )?;
        Ok(())
    }
}

impl<F: SonobeField> FCircuit for CircuitForTest<F> {
    type Field = F;
    type State = [F; 1];
    type StateVar = [FpVar<F>; 1];

    type ExternalInputs = ();
    type ExternalOutputs = ();

    fn dummy_state(&self) -> Self::State {
        [F::zero(); 1]
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {}

    fn generate_step_constraints(
        &self,
        _i: FpVar<Self::Field>,
        z_i: Self::StateVar,
        _external_inputs: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let cs = z_i.cs();

        let x = if let FpVar::Var(x) = z_i[0].clone() {
            x
        } else {
            unreachable!()
        };
        let y = AllocatedFp::new_witness(cs.clone(), || {
            Ok(x.value()?.pow([3]) + x.value()? + F::from(5))
        })?;

        let x_square = x.square()?;
        let x_cube = x_square.mul(&x);
        let t = AllocatedFp::new_witness(cs.clone(), || Ok(x.value()?.pow([3]) + x.value()?))?;
        let x_cube_plus_x = x.add(&x_cube);
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x.variable.into(),
            || Variable::one().into(),
            || t.variable.into(),
        )?;
        let x_cube_plus_x_plus_5 = t.add_constant(F::from(5));
        cs.enforce_r1cs_constraint(
            || x_cube_plus_x_plus_5.variable.into(),
            || Variable::one().into(),
            || y.variable.into(),
        )?;
        Ok(([FpVar::Var(x_cube_plus_x_plus_5)], ()))
    }
}

#[allow(non_snake_case)]
pub fn constraints_for_test<F: Field>() -> R1CS<F> {
    let A = vec![
        vec![(F::one(), 1)],
        vec![(F::one(), 3)],
        vec![(F::one(), 1), (F::one(), 4)],
        vec![(F::from(5), 0), (F::one(), 5)],
    ];
    let B = vec![
        vec![(F::one(), 1)],
        vec![(F::one(), 1)],
        vec![(F::one(), 0)],
        vec![(F::one(), 0)],
    ];
    let C = vec![
        vec![(F::one(), 3)],
        vec![(F::one(), 4)],
        vec![(F::one(), 5)],
        vec![(F::one(), 2)],
    ];

    R1CS::<F>::new(R1CSConfig::new(4, 6, 1), [A, B, C])
}

pub fn satisfying_assignments_for_test<F: Field>(x: F) -> Assignments<F, Vec<F>> {
    Assignments::from((
        F::one(),
        vec![x],
        vec![x * x * x + x + F::from(5), x * x, x * x * x, x * x * x + x],
    ))
}
