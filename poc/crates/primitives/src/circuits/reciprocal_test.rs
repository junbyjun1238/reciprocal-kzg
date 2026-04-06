use ark_ff::PrimeField;
use ark_r1cs_std::{GR1CSVar, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;
use thiserror::Error;

use crate::{circuits::FCircuit, traits::SonobeField};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalDescriptorError {
    #[error("singular reciprocal-shift descriptor update at c = {c}")]
    SingularShift { c: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReciprocalSeedDescriptorN4<F: PrimeField> {
    pub mu_1: [F; 4],
}

impl<F: PrimeField> ReciprocalSeedDescriptorN4<F> {
    pub fn new(mu_1: [F; 4]) -> Self {
        Self { mu_1 }
    }

    pub fn reduced_descriptor(&self) -> Result<[F; 4], ReciprocalDescriptorError> {
        reciprocal_shift_descriptor_update(self.mu_1, F::zero())
    }

    pub fn uniform_round_descriptors(&self) -> Result<[[F; 4]; 2], ReciprocalDescriptorError> {
        Ok([self.mu_1, self.reduced_descriptor()?])
    }
}

fn reciprocal_shift_descriptor_update<F: PrimeField>(
    mu_i: [F; 4],
    c: F,
) -> Result<[F; 4], ReciprocalDescriptorError> {
    let c2 = c * c;
    let c3 = c2 * c;
    let c4 = c3 * c;
    let d_c = c4 - mu_i[3] * c3 - mu_i[2] * c2 - mu_i[1] * c - mu_i[0];
    let d_inv = d_c
        .inverse()
        .ok_or(ReciprocalDescriptorError::SingularShift {
            c: c.into_bigint().as_ref()[0],
        })?;
    Ok([
        -d_inv,
        (mu_i[3] - F::from(4_u64) * c) * d_inv,
        (mu_i[2] + F::from(3_u64) * c * mu_i[3] - F::from(6_u64) * c2) * d_inv,
        (mu_i[1] + F::from(2_u64) * c * mu_i[2] + F::from(3_u64) * c2 * mu_i[3]
            - F::from(4_u64) * c3)
            * d_inv,
    ])
}

fn reciprocal_n4_from_leaves<F: PrimeField>(q: [F; 4], leaves: [F; 4]) -> ([F; 4], F) {
    let [x0, x1, x2, x3] = leaves;
    let s01_2 = x1 - x0;
    let s01_3 = x0;
    let s23_2 = x3 - x2;
    let s23_3 = x2;

    let delta2 = s23_2 - s01_2;
    let delta3 = s23_3 - s01_3;

    let u0 = q[0] * delta3;
    let u1 = q[1] * delta3;
    let u2 = s01_2 + q[2] * delta3;
    let u3 = s01_3 + delta2 + q[3] * delta3;

    let outputs = [
        u3,
        u2 + F::from(3_u64) * u3,
        u1 + F::from(2_u64) * u2 + F::from(3_u64) * u3,
        u0 + u1 + u2 + u3,
    ];
    let next_state = outputs.iter().copied().fold(F::zero(), |acc, y| acc + y);
    (outputs, next_state)
}

fn reciprocal_n4_constraints<F: SonobeField>(
    x: FpVar<F>,
    q: [FpVar<F>; 4],
    leaf_offsets: [FpVar<F>; 4],
) -> ([FpVar<F>; 4], FpVar<F>) {
    let x0 = x.clone() + leaf_offsets[0].clone();
    let x1 = x.clone() + leaf_offsets[1].clone();
    let x2 = x.clone() + leaf_offsets[2].clone();
    let x3 = x + leaf_offsets[3].clone();

    let s01_2 = x1 - x0.clone();
    let s01_3 = x0;
    let s23_2 = x3 - x2.clone();
    let s23_3 = x2;

    let delta2 = s23_2 - s01_2.clone();
    let delta3 = s23_3 - s01_3.clone();

    let u0 = q[0].clone() * delta3.clone();
    let u1 = q[1].clone() * delta3.clone();
    let u2 = s01_2 + q[2].clone() * delta3.clone();
    let u3 = s01_3 + delta2 + q[3].clone() * delta3;

    let two = FpVar::Constant(F::from(2_u64));
    let three = FpVar::Constant(F::from(3_u64));
    let outputs = [
        u3.clone(),
        u2.clone() + three.clone() * u3.clone(),
        u1.clone() + two * u2.clone() + three * u3.clone(),
        u0.clone() + u1 + u2 + u3,
    ];
    let next_state =
        outputs[0].clone() + outputs[1].clone() + outputs[2].clone() + outputs[3].clone();
    (outputs, next_state)
}

fn reciprocal_output_values<F: SonobeField>(
    outputs: [FpVar<F>; 4],
) -> Result<[F; 4], SynthesisError> {
    if outputs[0].cs().is_in_setup_mode() {
        return Ok([F::zero(); 4]);
    }

    Ok([
        outputs[0].value()?,
        outputs[1].value()?,
        outputs[2].value()?,
        outputs[3].value()?,
    ])
}

pub struct ReciprocalCircuitForTest<F: PrimeField> {
    pub q: [F; 4],
    pub leaf_offsets: [F; 4],
}

impl<F: PrimeField> ReciprocalCircuitForTest<F> {
    pub fn from_seed_descriptor(
        seed: ReciprocalSeedDescriptorN4<F>,
        leaf_offsets: [F; 4],
    ) -> Result<Self, ReciprocalDescriptorError> {
        Ok(Self {
            q: seed.reduced_descriptor()?,
            leaf_offsets,
        })
    }

    pub fn leaf_vector(&self, x: F) -> [F; 4] {
        core::array::from_fn(|i| x + self.leaf_offsets[i])
    }

    pub fn evaluate(&self, x: F) -> ([F; 4], F) {
        reciprocal_n4_from_leaves(self.q, self.leaf_vector(x))
    }
}

pub struct NaiveReciprocalCircuitForTest<F: PrimeField> {
    pub q: [F; 4],
    pub leaf_offsets: [F; 4],
}

impl<F: PrimeField> NaiveReciprocalCircuitForTest<F> {
    pub fn from_seed_descriptor(
        seed: ReciprocalSeedDescriptorN4<F>,
        leaf_offsets: [F; 4],
    ) -> Result<Self, ReciprocalDescriptorError> {
        Ok(Self {
            q: seed.reduced_descriptor()?,
            leaf_offsets,
        })
    }

    pub fn initial_state(&self, x: F) -> [F; 9] {
        [
            x,
            self.q[0],
            self.q[1],
            self.q[2],
            self.q[3],
            self.leaf_offsets[0],
            self.leaf_offsets[1],
            self.leaf_offsets[2],
            self.leaf_offsets[3],
        ]
    }

    pub fn evaluate_state(&self, state: [F; 9]) -> ([F; 4], [F; 9]) {
        let x = state[0];
        let q = [state[1], state[2], state[3], state[4]];
        let leaf_offsets = [state[5], state[6], state[7], state[8]];
        let leaves = core::array::from_fn(|i| x + leaf_offsets[i]);
        let (outputs, next_x) = reciprocal_n4_from_leaves(q, leaves);
        let next_state = [
            next_x,
            q[0],
            q[1],
            q[2],
            q[3],
            leaf_offsets[0],
            leaf_offsets[1],
            leaf_offsets[2],
            leaf_offsets[3],
        ];
        (outputs, next_state)
    }
}

impl<F: SonobeField> FCircuit for ReciprocalCircuitForTest<F> {
    type Field = F;
    type State = [F; 1];
    type StateVar = [FpVar<F>; 1];

    type ExternalInputs = ();
    type ExternalOutputs = [F; 4];

    fn dummy_state(&self) -> Self::State {
        [F::zero(); 1]
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {}

    fn generate_step_constraints(
        &self,
        _i: FpVar<Self::Field>,
        state: Self::StateVar,
        _external_inputs: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let q = self.q.map(FpVar::Constant);
        let leaf_offsets = self.leaf_offsets.map(FpVar::Constant);
        let (outputs, next_state) = reciprocal_n4_constraints(state[0].clone(), q, leaf_offsets);
        let outputs = reciprocal_output_values(outputs)?;

        Ok(([next_state], outputs))
    }
}

impl<F: SonobeField> FCircuit for NaiveReciprocalCircuitForTest<F> {
    type Field = F;
    type State = [F; 9];
    type StateVar = [FpVar<F>; 9];

    type ExternalInputs = ();
    type ExternalOutputs = [F; 4];

    fn dummy_state(&self) -> Self::State {
        self.initial_state(F::zero())
    }

    fn dummy_external_inputs(&self) -> Self::ExternalInputs {}

    fn generate_step_constraints(
        &self,
        _i: FpVar<Self::Field>,
        state: Self::StateVar,
        _external_inputs: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError> {
        let x = state[0].clone();
        let q = [
            state[1].clone(),
            state[2].clone(),
            state[3].clone(),
            state[4].clone(),
        ];
        let leaf_offsets = [
            state[5].clone(),
            state[6].clone(),
            state[7].clone(),
            state[8].clone(),
        ];
        let (outputs, next_x) = reciprocal_n4_constraints(x, q.clone(), leaf_offsets.clone());
        let outputs = reciprocal_output_values(outputs)?;

        Ok((
            [
                next_x,
                q[0].clone(),
                q[1].clone(),
                q[2].clone(),
                q[3].clone(),
                leaf_offsets[0].clone(),
                leaf_offsets[1].clone(),
                leaf_offsets[2].clone(),
                leaf_offsets[3].clone(),
            ],
            outputs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::error::Error;

    use super::{
        NaiveReciprocalCircuitForTest, ReciprocalCircuitForTest, ReciprocalSeedDescriptorN4,
        reciprocal_shift_descriptor_update,
    };
    use crate::circuits::FCircuit;

    fn sample_seed_descriptor() -> ReciprocalSeedDescriptorN4<Fr> {
        ReciprocalSeedDescriptorN4::new([
            Fr::from(1_u64),
            -Fr::from(4_u64),
            -Fr::from(3_u64),
            -Fr::from(2_u64),
        ])
    }

    #[test]
    fn test_reciprocal_circuit_for_test() -> Result<(), Box<dyn Error>> {
        let circuit = ReciprocalCircuitForTest::from_seed_descriptor(
            sample_seed_descriptor(),
            [
                Fr::from(0_u64),
                Fr::from(1_u64),
                Fr::from(2_u64),
                Fr::from(3_u64),
            ],
        )?;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::zero()))?;
        let state = <[FpVar<Fr>; 1] as AllocVar<[Fr; 1], Fr>>::new_witness(cs.clone(), || {
            Ok([Fr::from(3_u64)])
        })?;

        let (next_state, outputs) = circuit.generate_step_constraints(i, state, ())?;
        let (expected_outputs, expected_next_state) = circuit.evaluate(Fr::from(3_u64));

        assert!(cs.is_satisfied()?);
        assert_eq!(outputs, expected_outputs);
        assert_eq!(next_state[0].value()?, expected_next_state);

        Ok(())
    }

    #[test]
    fn test_naive_reciprocal_circuit_for_test() -> Result<(), Box<dyn Error>> {
        let circuit = NaiveReciprocalCircuitForTest::from_seed_descriptor(
            sample_seed_descriptor(),
            [
                Fr::from(0_u64),
                Fr::from(1_u64),
                Fr::from(2_u64),
                Fr::from(3_u64),
            ],
        )?;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::zero()))?;
        let state = <[FpVar<Fr>; 9] as AllocVar<[Fr; 9], Fr>>::new_witness(cs.clone(), || {
            Ok(circuit.initial_state(Fr::from(3_u64)))
        })?;

        let (next_state, outputs) = circuit.generate_step_constraints(i, state, ())?;
        let (expected_outputs, expected_next_state) =
            circuit.evaluate_state(circuit.initial_state(Fr::from(3_u64)));

        assert!(cs.is_satisfied()?);
        assert_eq!(outputs, expected_outputs);
        assert_eq!(next_state.value()?, expected_next_state);

        Ok(())
    }

    #[test]
    fn test_reciprocal_circuit_matches_worked_n4_matrix_formula() {
        let circuit = ReciprocalCircuitForTest::from_seed_descriptor(
            sample_seed_descriptor(),
            [
                Fr::from(0_u64),
                Fr::from(1_u64),
                Fr::from(2_u64),
                Fr::from(3_u64),
            ],
        )
        .expect("sample seed descriptor should expand");
        let x = Fr::from(7_u64);
        let leaves = circuit.leaf_vector(x);
        let (outputs, _) = circuit.evaluate(x);
        let mu_sum = circuit
            .q
            .into_iter()
            .fold(Fr::zero(), |acc, value| acc + value);
        let expected = [
            (Fr::from(2_u64) - circuit.q[3]) * leaves[0] - leaves[1]
                + (circuit.q[3] - Fr::from(1_u64)) * leaves[2]
                + leaves[3],
            (Fr::from(5_u64) - circuit.q[2] - Fr::from(3_u64) * circuit.q[3]) * leaves[0]
                - Fr::from(2_u64) * leaves[1]
                + (circuit.q[2] + Fr::from(3_u64) * circuit.q[3] - Fr::from(3_u64)) * leaves[2]
                + Fr::from(3_u64) * leaves[3],
            (Fr::from(4_u64)
                - circuit.q[1]
                - Fr::from(2_u64) * circuit.q[2]
                - Fr::from(3_u64) * circuit.q[3])
                * leaves[0]
                - leaves[1]
                + (circuit.q[1] + Fr::from(2_u64) * circuit.q[2] + Fr::from(3_u64) * circuit.q[3]
                    - Fr::from(3_u64))
                    * leaves[2]
                + Fr::from(3_u64) * leaves[3],
            (Fr::from(1_u64) - mu_sum) * leaves[0]
                + (mu_sum - Fr::from(1_u64)) * leaves[2]
                + leaves[3],
        ];

        assert_eq!(outputs, expected);
    }

    #[test]
    fn test_seed_descriptor_expands_to_reduced_descriptor() -> Result<(), Box<dyn Error>> {
        let q = sample_seed_descriptor().reduced_descriptor()?;
        assert_eq!(
            q,
            [
                Fr::from(1_u64),
                Fr::from(2_u64),
                Fr::from(3_u64),
                Fr::from(4_u64)
            ]
        );
        Ok(())
    }

    #[test]
    fn test_seed_descriptor_uniform_round_descriptors() -> Result<(), Box<dyn Error>> {
        let seed = sample_seed_descriptor();
        let uniform = seed.uniform_round_descriptors()?;
        assert_eq!(uniform[0], seed.mu_1);
        assert_eq!(
            uniform[1],
            [
                Fr::from(1_u64),
                Fr::from(2_u64),
                Fr::from(3_u64),
                Fr::from(4_u64)
            ]
        );
        Ok(())
    }

    #[test]
    fn test_descriptor_update_rejects_singular_shift() {
        assert!(reciprocal_shift_descriptor_update([Fr::zero(); 4], Fr::zero()).is_err());
    }
}
