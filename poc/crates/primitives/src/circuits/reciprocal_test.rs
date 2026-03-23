//! Test circuits for reciprocal-style PoC integration.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    fields::fp::FpVar,
};
use ark_relations::gr1cs::SynthesisError;
use thiserror::Error;

use crate::{circuits::FCircuit, traits::SonobeField};

/// [`ReciprocalDescriptorError`] enumerates failures while expanding the
/// worked `N = 4` reciprocal descriptor.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalDescriptorError {
    /// The reciprocal-shift update denominator vanished.
    #[error("singular reciprocal-shift descriptor update at c = {c}")]
    SingularShift {
        /// Affine shift parameter at which the denominator vanished.
        c: u64,
    },
}

/// [`ReciprocalSeedDescriptorN4`] stores the algebraic seed data needed to
/// expand the worked `N = 4` reciprocal descriptor.
///
/// In the note, the ambient seed is `(n, tau)`. The current PoC does not yet
/// fix an in-repo quartic extension representation for `tau`, so the exact
/// algebraic input we keep here is `mu_1`, the coefficient tuple of the monic
/// minimal polynomial of `tau`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReciprocalSeedDescriptorN4<F: PrimeField> {
    /// Coefficient tuple `mu_1 = (mu_{1,0}, mu_{1,1}, mu_{1,2}, mu_{1,3})`.
    pub mu_1: [F; 4],
}

impl<F: PrimeField> ReciprocalSeedDescriptorN4<F> {
    /// Creates a worked `N = 4` seed descriptor from the round-1 coefficient
    /// tuple `mu_1`.
    pub fn new(mu_1: [F; 4]) -> Self {
        Self { mu_1 }
    }

    /// Expands the reduced descriptor `q = mu_2` used by the worked `N = 4`
    /// evaluator.
    ///
    /// This is the exact `c = 0` specialization of Proposition
    /// `Reciprocal-shift minimal-polynomial update` from the note.
    pub fn reduced_descriptor(&self) -> Result<[F; 4], ReciprocalDescriptorError> {
        reciprocal_shift_descriptor_update(self.mu_1, F::zero())
    }

    /// Returns the uniform per-round descriptor `[mu_1, mu_2]`.
    ///
    /// For the evaluator itself only `mu_2` is needed, but keeping `mu_1`
    /// alongside it mirrors the note's reduced-versus-uniform distinction.
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

/// [`ReciprocalCircuitForTest`] is a minimal `FCircuit` for the exact worked
/// reciprocal evaluator at `N = 4`.
///
/// The step state remains a single scalar `x`, while each step instantiates the
/// real round-by-round reciprocal recurrence on the derived leaf vector
/// `[x + o_0, x + o_1, x + o_2, x + o_3]`. The public descriptor `q`
/// corresponds to the worked-example tuple `mu_2`.
pub struct ReciprocalCircuitForTest<F: PrimeField> {
    /// Fixed descriptor tuple `mu_2`.
    pub q: [F; 4],
    /// Fixed public offsets used to derive the 4-leaf input vector from the
    /// current scalar state.
    pub leaf_offsets: [F; 4],
}

impl<F: PrimeField> ReciprocalCircuitForTest<F> {
    /// Builds the worked `N = 4` reciprocal circuit from a seed descriptor.
    pub fn from_seed_descriptor(
        seed: ReciprocalSeedDescriptorN4<F>,
        leaf_offsets: [F; 4],
    ) -> Result<Self, ReciprocalDescriptorError> {
        Ok(Self {
            q: seed.reduced_descriptor()?,
            leaf_offsets,
        })
    }

    /// Returns the concrete `N = 4` leaf vector instantiated by the current
    /// state value `x`.
    pub fn leaf_vector(&self, x: F) -> [F; 4] {
        core::array::from_fn(|i| x + self.leaf_offsets[i])
    }

    /// Evaluates the circuit's out-of-circuit transition on a concrete state
    /// value `x` using the exact worked `N = 4` reciprocal recurrence.
    pub fn evaluate(&self, x: F) -> ([F; 4], F) {
        reciprocal_n4_from_leaves(self.q, self.leaf_vector(x))
    }
}

/// [`NaiveReciprocalCircuitForTest`] is a baseline `FCircuit` that carries the
/// descriptor and leaf-family metadata inside the step state instead of
/// specializing it in the circuit configuration.
///
/// The state is `[x, q_0, q_1, q_2, q_3, o_0, o_1, o_2, o_3]`, so each step
/// keeps re-carrying the reciprocal descriptor and leaf instantiation metadata.
pub struct NaiveReciprocalCircuitForTest<F: PrimeField> {
    /// Initial descriptor tuple used to seed the state.
    pub q: [F; 4],
    /// Initial public offsets used to seed the state.
    pub leaf_offsets: [F; 4],
}

impl<F: PrimeField> NaiveReciprocalCircuitForTest<F> {
    /// Builds the naive worked `N = 4` reciprocal circuit from a seed
    /// descriptor.
    pub fn from_seed_descriptor(
        seed: ReciprocalSeedDescriptorN4<F>,
        leaf_offsets: [F; 4],
    ) -> Result<Self, ReciprocalDescriptorError> {
        Ok(Self {
            q: seed.reduced_descriptor()?,
            leaf_offsets,
        })
    }

    /// Returns the concrete state layout used by the naive baseline.
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

    /// Evaluates the out-of-circuit transition on the full naive state using
    /// the exact worked `N = 4` reciprocal recurrence.
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
        let (outputs, next_state) =
            reciprocal_n4_constraints(state[0].clone(), q, leaf_offsets);
        let outputs = [
            outputs[0].value().unwrap_or_default(),
            outputs[1].value().unwrap_or_default(),
            outputs[2].value().unwrap_or_default(),
            outputs[3].value().unwrap_or_default(),
        ];

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
        let outputs = [
            outputs[0].value().unwrap_or_default(),
            outputs[1].value().unwrap_or_default(),
            outputs[2].value().unwrap_or_default(),
            outputs[3].value().unwrap_or_default(),
        ];

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
            [Fr::from(0_u64), Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64)],
        )?;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::zero()))?;
        let state =
            <[FpVar<Fr>; 1] as AllocVar<[Fr; 1], Fr>>::new_witness(cs.clone(), || {
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
            [Fr::from(0_u64), Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64)],
        )?;

        let cs = ConstraintSystem::<Fr>::new_ref();
        let i = FpVar::new_witness(cs.clone(), || Ok(Fr::zero()))?;
        let state =
            <[FpVar<Fr>; 9] as AllocVar<[Fr; 9], Fr>>::new_witness(cs.clone(), || {
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
            [Fr::from(0_u64), Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64)],
        )
        .expect("sample seed descriptor should expand");
        let x = Fr::from(7_u64);
        let leaves = circuit.leaf_vector(x);
        let (outputs, _) = circuit.evaluate(x);
        let mu_sum = circuit.q.into_iter().fold(Fr::zero(), |acc, value| acc + value);
        let expected = [
            (Fr::from(2_u64) - circuit.q[3]) * leaves[0] - leaves[1]
                + (circuit.q[3] - Fr::from(1_u64)) * leaves[2]
                + leaves[3],
            (Fr::from(5_u64) - circuit.q[2] - Fr::from(3_u64) * circuit.q[3]) * leaves[0]
                - Fr::from(2_u64) * leaves[1]
                + (circuit.q[2] + Fr::from(3_u64) * circuit.q[3] - Fr::from(3_u64))
                    * leaves[2]
                + Fr::from(3_u64) * leaves[3],
            (Fr::from(4_u64)
                - circuit.q[1]
                - Fr::from(2_u64) * circuit.q[2]
                - Fr::from(3_u64) * circuit.q[3])
                * leaves[0]
                - leaves[1]
                + (circuit.q[1]
                    + Fr::from(2_u64) * circuit.q[2]
                    + Fr::from(3_u64) * circuit.q[3]
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
            [Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64), Fr::from(4_u64)]
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
            [Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64), Fr::from(4_u64)]
        );
        Ok(())
    }

    #[test]
    fn test_descriptor_update_rejects_singular_shift() {
        assert!(reciprocal_shift_descriptor_update([Fr::zero(); 4], Fr::zero()).is_err());
    }
}
