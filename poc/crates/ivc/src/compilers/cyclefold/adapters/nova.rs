use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean, GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    nova::{CycleFoldNova, Nova},
    FoldingSchemeDefGadget,
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bounds, EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
        ops::bits::{FromBits, FromBitsGadget, ToBitsGadgetExt},
    },
    circuits::WitnessToPublic,
    commitments::GroupBasedCommitment,
    traits::{SonobeCurve, CF2},
};

use crate::compilers::cyclefold::{
    circuits::CycleFoldCircuit, CycleFoldBasedIVC, FoldingSchemeCycleFoldExt,
};

pub struct NovaCycleFoldCircuit<C, const CHALLENGE_BITS: usize> {
    r: Vec<bool>,
    points: Vec<C>,
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> Default
    for NovaCycleFoldCircuit<C, CHALLENGE_BITS>
{
    fn default() -> Self {
        Self {
            r: vec![false; CHALLENGE_BITS],
            points: vec![C::zero(); 2],
        }
    }
}

impl<C: SonobeCurve, const CHALLENGE_BITS: usize> CycleFoldCircuit<CF2<C>>
    for NovaCycleFoldCircuit<C, CHALLENGE_BITS>
{
    fn enforce_point_rlc(&self, cs: ConstraintSystemRef<CF2<C>>) -> Result<(), SynthesisError> {
        let rho = FpVar::new_input(cs.clone(), || Ok(CF2::<C>::from_bits_le(&self.r[..])))?;
        let rho_bits = rho.to_n_bits_le(CHALLENGE_BITS)?;

        let points = Vec::<C::Var>::new_witness(cs.clone(), || Ok(&self.points[..]))?;
        points.mark_as_public()?;

        (points[1].scalar_mul_le(rho_bits.iter())? + &points[0]).mark_as_public()
    }
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeCycleFoldExt<1, 1>
    for Nova<CM, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 2;

    type CFCircuit = NovaCycleFoldCircuit<CM::Commitment, CHALLENGE_BITS>;

    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        [running_instance]: &[impl Borrow<Self::RU>; 1],
        [incoming_instance]: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
        challenge: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        vec![
            NovaCycleFoldCircuit {
                r: challenge.into(),
                points: vec![running_instance.borrow().cm_e, *proof],
            },
            NovaCycleFoldCircuit {
                r: challenge.into(),
                points: vec![
                    running_instance.borrow().cm_w,
                    incoming_instance.borrow().cm_w,
                ],
            },
        ]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        [running_instance]: [<Self::Verifier as FoldingSchemeDefGadget>::RU; 1],
        [incoming_instance]: [<Self::Verifier as FoldingSchemeDefGadget>::IU; 1],
        next_running_instance: <Self::Verifier as FoldingSchemeDefGadget>::RU,
        proof: <Self::Verifier as FoldingSchemeDefGadget>::Proof<1, 1>,
        challenge: <Self::Verifier as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut challenge_bits = challenge.to_vec();
        challenge_bits.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let challenge = EmulatedFieldVar::from_bounded_bits_le(
            &challenge_bits,
            Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
        )?;
        Ok(vec![
            once(challenge.clone())
                .chain(
                    [running_instance.cm_e, proof, next_running_instance.cm_e]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(challenge)
                .chain(
                    [
                        running_instance.cm_w,
                        incoming_instance.cm_w,
                        next_running_instance.cm_w,
                    ]
                    .into_iter()
                    .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
        ])
    }
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> FoldingSchemeCycleFoldExt<2, 0>
    for Nova<CM, CHALLENGE_BITS>
{
    const N_CYCLEFOLDS: usize = 3;

    type CFCircuit = NovaCycleFoldCircuit<CM::Commitment, CHALLENGE_BITS>;

    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        [left_running_instance, right_running_instance]: &[impl Borrow<Self::RU>; 2],
        _: &[impl Borrow<Self::IU>; 0],
        proof: &Self::Proof<2, 0>,
        challenge: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        let challenge_scalar = CM::Scalar::from_bits_le(&challenge);
        vec![
            NovaCycleFoldCircuit {
                r: challenge.into(),
                points: vec![*proof, right_running_instance.borrow().cm_e],
            },
            NovaCycleFoldCircuit {
                r: challenge.into(),
                points: vec![
                    left_running_instance.borrow().cm_e,
                    right_running_instance.borrow().cm_e * challenge_scalar + proof,
                ],
            },
            NovaCycleFoldCircuit {
                r: challenge.into(),
                points: vec![
                    left_running_instance.borrow().cm_w,
                    right_running_instance.borrow().cm_w,
                ],
            },
        ]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        [left_running_instance, right_running_instance]: [<Self::Verifier as FoldingSchemeDefGadget>::RU;
            2],
        _: [<Self::Verifier as FoldingSchemeDefGadget>::IU; 0],
        next_running_instance: <Self::Verifier as FoldingSchemeDefGadget>::RU,
        proof: <Self::Verifier as FoldingSchemeDefGadget>::Proof<2, 0>,
        challenge_bits: <Self::Verifier as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut challenge_bits = challenge_bits.to_vec();
        challenge_bits.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let challenge = EmulatedFieldVar::from_bounded_bits_le(
            &challenge_bits,
            Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
        )?;
        let combined_commitment_cs = right_running_instance
            .cm_e
            .cs()
            .or(proof.cs())
            .or(challenge_bits.cs());
        let combined_commitment =
            EmulatedAffineVar::new_witness(combined_commitment_cs.clone(), || {
                if combined_commitment_cs.is_in_setup_mode() {
                    return Ok(Default::default());
                }
                let challenge_bits = challenge_bits.value()?;
                let challenge_scalar = CM::Scalar::from_bits_le(&challenge_bits);
                let proof_value = proof.value()?;
                let right_running_value = right_running_instance.cm_e.value()?;
                Ok(proof_value + right_running_value * challenge_scalar)
            })?;
        Ok(vec![
            once(challenge.clone())
                .chain(
                    [
                        proof,
                        right_running_instance.cm_e,
                        combined_commitment.clone(),
                    ]
                    .into_iter()
                    .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(challenge.clone())
                .chain(
                    [
                        left_running_instance.cm_e,
                        combined_commitment,
                        next_running_instance.cm_e,
                    ]
                    .into_iter()
                    .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(challenge)
                .chain(
                    [
                        left_running_instance.cm_w,
                        right_running_instance.cm_w,
                        next_running_instance.cm_w,
                    ]
                    .into_iter()
                    .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
        ])
    }
}

pub type NovaNovaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Projective as C1};
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective as C2;
    use ark_std::{
        error::Error,
        rand::{thread_rng, RngCore},
        sync::Arc,
    };
    use sonobe_primitives::{
        circuits::{
            reciprocal_test::{NaiveReciprocalCircuitForTest, ReciprocalCircuitForTest},
            utils::CircuitForTest,
            FCircuit,
        },
        commitments::{pedersen::Pedersen, CommitmentOps},
        traits::Dummy,
        transcripts::griffin::{sponge::GriffinSponge, GriffinParams},
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{
        compilers::cyclefold::adapters::{
            reciprocal::{ReciprocalAdapterError, ReciprocalCycleFoldAdapter},
            reciprocal_bench::{
                benchmark_snapshot_rows, sample_naive_reciprocal_circuit,
                sample_reciprocal_circuit, BenchmarkSnapshotRow,
            },
            reciprocal_types::{
                reciprocal_n4_trace_and_output, ReciprocalSameQLane, ReciprocalTypeError,
                ReciprocalWitness,
            },
            reciprocal_wrapper::ReciprocalWrapperError,
        },
        tests::run_ivc_smoke_test,
        IVC,
    };

    type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

    fn setup_reciprocal_ivc(
        rng: &mut impl RngCore,
    ) -> Result<
        (
            ReciprocalCircuitForTest<Fr>,
            ReciprocalSameQLane<Pedersen<C1, true>>,
            <TestIVC as IVC>::ProverKey<ReciprocalCircuitForTest<Fr>>,
            <TestIVC as IVC>::VerifierKey<ReciprocalCircuitForTest<Fr>>,
        ),
        Box<dyn Error>,
    > {
        let step_circuit = sample_reciprocal_circuit()?;
        let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(step_circuit.q.to_vec())?;
        let pp = TestIVC::preprocess(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            &mut *rng,
        )?;
        let (pk, vk) = TestIVC::generate_keys(pp, &step_circuit)?;
        Ok((step_circuit, lane, pk, vk))
    }

    fn assert_reciprocal_opening_statement(
        step_circuit: &ReciprocalCircuitForTest<Fr>,
        lane: &ReciprocalSameQLane<Pedersen<C1, true>>,
        current_state: &<ReciprocalCircuitForTest<Fr> as FCircuit>::State,
        external_outputs: <ReciprocalCircuitForTest<Fr> as FCircuit>::ExternalOutputs,
        rng: &mut impl RngCore,
    ) -> Result<(), Box<dyn Error>> {
        let leaf_vector = step_circuit.leaf_vector(current_state[0]).to_vec();
        let ck = <Pedersen<C1, true> as CommitmentOps>::generate_key(leaf_vector.len(), &mut *rng)?;
        let (cm_x, omega) =
            <Pedersen<C1, true> as CommitmentOps>::commit(&ck, &leaf_vector, &mut *rng)?;
        let (trace, expected_y) = reciprocal_n4_trace_and_output(lane.descriptor(), &leaf_vector)?;
        assert_eq!(external_outputs, expected_y);
        let witness = ReciprocalWitness {
            x: leaf_vector,
            trace,
            omega,
        };
        let instance = lane.bind_instance(cm_x, external_outputs);
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, lane, &instance, witness,
        )?;
        ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(&ck, lane, &statement)?;
        Ok(())
    }

    #[test]
    fn test_nova_ivc_roundtrip() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        run_ivc_smoke_test::<
            NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>,
            _,
        >(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            vec![(); 20],
            &mut rng,
        )?;

        Ok(())
    }

    #[test]
    fn test_reciprocal_ivc_outputs_match_circuit() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let (step_circuit, lane, pk, vk) = setup_reciprocal_ivc(&mut rng)?;

        let initial_state = step_circuit.dummy_state();
        let mut current_state = initial_state;
        let mut current_proof = <TestIVC as IVC>::Proof::<ReciprocalCircuitForTest<Fr>>::dummy(&pk);

        for step in 0..3 {
            let (expected_outputs, expected_next_state) = step_circuit.evaluate(current_state[0]);
            let (next_state, external_outputs, next_proof) = TestIVC::prove(
                &pk,
                &step_circuit,
                step,
                &initial_state,
                &current_state,
                (),
                &current_proof,
                &mut rng,
            )?;

            assert_eq!(external_outputs, expected_outputs);
            assert_eq!(next_state, [expected_next_state]);
            TestIVC::verify::<ReciprocalCircuitForTest<Fr>>(
                &vk,
                step + 1,
                &initial_state,
                &next_state,
                &next_proof,
            )?;
            assert_reciprocal_opening_statement(
                &step_circuit,
                &lane,
                &current_state,
                external_outputs,
                &mut rng,
            )?;

            current_state = next_state;
            current_proof = next_proof;
        }

        Ok(())
    }

    #[test]
    fn test_reciprocal_statement_rejects_tampered_output() -> Result<(), Box<dyn Error>> {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let mut rng = thread_rng();
        let step_circuit = sample_reciprocal_circuit()?;
        let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(step_circuit.q.to_vec())?;

        let pp = TestIVC::preprocess(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            &mut rng,
        )?;
        let (pk, vk) = TestIVC::generate_keys(pp, &step_circuit)?;

        let initial_state = step_circuit.dummy_state();
        let current_proof = <TestIVC as IVC>::Proof::<ReciprocalCircuitForTest<Fr>>::dummy(&pk);
        let (next_state, external_outputs, next_proof) = TestIVC::prove(
            &pk,
            &step_circuit,
            0,
            &initial_state,
            &initial_state,
            (),
            &current_proof,
            &mut rng,
        )?;

        TestIVC::verify::<ReciprocalCircuitForTest<Fr>>(
            &vk,
            1,
            &initial_state,
            &next_state,
            &next_proof,
        )?;

        let leaf_vector = step_circuit.leaf_vector(initial_state[0]).to_vec();
        let ck = <Pedersen<C1, true> as CommitmentOps>::generate_key(leaf_vector.len(), &mut rng)?;
        let (cm_x, omega) =
            <Pedersen<C1, true> as CommitmentOps>::commit(&ck, &leaf_vector, &mut rng)?;
        let (trace, expected_y) = reciprocal_n4_trace_and_output(lane.descriptor(), &leaf_vector)?;
        assert_eq!(external_outputs, expected_y);
        let witness = ReciprocalWitness {
            x: leaf_vector,
            trace,
            omega,
        };
        let instance = lane.bind_instance(cm_x, external_outputs);
        let mut statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, &lane, &instance, witness,
        )?;
        statement.instance.y[0] += Fr::from(1_u64);

        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(&ck, &lane, &statement),
            Err(ReciprocalAdapterError::Wrapper(
                ReciprocalWrapperError::OutputMismatch { coordinate: 0 }
            ))
        );

        Ok(())
    }

    #[test]
    fn test_reciprocal_statement_rejects_wrong_lane() -> Result<(), Box<dyn Error>> {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let mut rng = thread_rng();
        let step_circuit = sample_reciprocal_circuit()?;
        let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(step_circuit.q.to_vec())?;
        let wrong_lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(vec![
            Fr::from(9_u64),
            Fr::from(9_u64),
            Fr::from(9_u64),
            Fr::from(9_u64),
        ])?;

        let pp = TestIVC::preprocess(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            &mut rng,
        )?;
        let (pk, vk) = TestIVC::generate_keys(pp, &step_circuit)?;

        let initial_state = step_circuit.dummy_state();
        let current_proof = <TestIVC as IVC>::Proof::<ReciprocalCircuitForTest<Fr>>::dummy(&pk);
        let (next_state, external_outputs, next_proof) = TestIVC::prove(
            &pk,
            &step_circuit,
            0,
            &initial_state,
            &initial_state,
            (),
            &current_proof,
            &mut rng,
        )?;

        TestIVC::verify::<ReciprocalCircuitForTest<Fr>>(
            &vk,
            1,
            &initial_state,
            &next_state,
            &next_proof,
        )?;

        let leaf_vector = step_circuit.leaf_vector(initial_state[0]).to_vec();
        let ck = <Pedersen<C1, true> as CommitmentOps>::generate_key(leaf_vector.len(), &mut rng)?;
        let (cm_x, omega) =
            <Pedersen<C1, true> as CommitmentOps>::commit(&ck, &leaf_vector, &mut rng)?;
        let (trace, expected_y) = reciprocal_n4_trace_and_output(lane.descriptor(), &leaf_vector)?;
        assert_eq!(external_outputs, expected_y);
        let witness = ReciprocalWitness {
            x: leaf_vector,
            trace,
            omega,
        };
        let instance = lane.bind_instance(cm_x, external_outputs);
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, &lane, &instance, witness,
        )?;

        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(
                &ck,
                &wrong_lane,
                &statement
            ),
            Err(ReciprocalAdapterError::Type(
                ReciprocalTypeError::DescriptorMismatch
            ))
        );

        Ok(())
    }

    #[test]
    fn test_naive_reciprocal_ivc_outputs_match_circuit() -> Result<(), Box<dyn Error>> {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let mut rng = thread_rng();
        let step_circuit = sample_naive_reciprocal_circuit()?;

        let pp = TestIVC::preprocess(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            &mut rng,
        )?;
        let (pk, vk) = TestIVC::generate_keys(pp, &step_circuit)?;

        let initial_state = step_circuit.dummy_state();
        let mut current_state = initial_state;
        let mut current_proof =
            <TestIVC as IVC>::Proof::<NaiveReciprocalCircuitForTest<Fr>>::dummy(&pk);

        for step in 0..3 {
            let (expected_outputs, expected_next_state) =
                step_circuit.evaluate_state(current_state);
            let (next_state, external_outputs, next_proof) = TestIVC::prove(
                &pk,
                &step_circuit,
                step,
                &initial_state,
                &current_state,
                (),
                &current_proof,
                &mut rng,
            )?;

            assert_eq!(external_outputs, expected_outputs);
            assert_eq!(next_state, expected_next_state);

            TestIVC::verify::<NaiveReciprocalCircuitForTest<Fr>>(
                &vk,
                step + 1,
                &initial_state,
                &next_state,
                &next_proof,
            )?;

            current_state = next_state;
            current_proof = next_proof;
        }

        Ok(())
    }

    #[test]
    #[ignore = "benchmark-style snapshot; run explicitly with --ignored --nocapture"]
    fn benchmark_nova_nova_snapshot() -> Result<(), Box<dyn Error>> {
        let [stock_row, naive_row, reciprocal_row] = benchmark_snapshot_rows()?;

        println!("{}", BenchmarkSnapshotRow::csv_header());
        println!("{}", stock_row.csv_row());
        println!("{}", naive_row.csv_row());
        println!("{}", reciprocal_row.csv_row());

        Ok(())
    }
}
