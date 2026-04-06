use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{
    GR1CSVar, alloc::AllocVar, fields::fp::FpVar, groups::CurveVar, prelude::Boolean,
};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{borrow::Borrow, iter::once};
use sonobe_fs::{
    FoldingSchemeDefGadget,
    nova::{CycleFoldNova, Nova},
};
use sonobe_primitives::{
    algebra::{
        field::emulated::{Bounds, EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
        ops::bits::{FromBits, FromBitsGadget, ToBitsGadgetExt},
    },
    circuits::WitnessToPublic,
    commitments::GroupBasedCommitment,
    traits::{CF2, SonobeCurve},
};

use crate::compilers::cyclefold::{
    CycleFoldBasedIVC, FoldingSchemeCycleFoldExt, circuits::CycleFoldCircuit,
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
        [U]: &[impl Borrow<Self::RU>; 1],
        [u]: &[impl Borrow<Self::IU>; 1],
        proof: &Self::Proof<1, 1>,
        rho: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        vec![
            NovaCycleFoldCircuit {
                r: rho.into(),
                points: vec![U.borrow().cm_e, *proof],
            },
            NovaCycleFoldCircuit {
                r: rho.into(),
                points: vec![U.borrow().cm_w, u.borrow().cm_w],
            },
        ]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        [U]: [<Self::Gadget as FoldingSchemeDefGadget>::RU; 1],
        [u]: [<Self::Gadget as FoldingSchemeDefGadget>::IU; 1],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<1, 1>,
        rho: <Self::Gadget as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut rho = rho.to_vec();
        rho.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let rho = EmulatedFieldVar::from_bounded_bits_le(
            &rho,
            Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
        )?;
        Ok(vec![
            once(rho.clone())
                .chain(
                    [U.cm_e, proof, UU.cm_e]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(rho)
                .chain(
                    [U.cm_w, u.cm_w, UU.cm_w]
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
        [U1, U2]: &[impl Borrow<Self::RU>; 2],
        _: &[impl Borrow<Self::IU>; 0],
        proof: &Self::Proof<2, 0>,
        rho_bits: Self::Challenge,
    ) -> Vec<Self::CFCircuit> {
        let rho = CM::Scalar::from_bits_le(&rho_bits);
        vec![
            NovaCycleFoldCircuit {
                r: rho_bits.into(),
                points: vec![*proof, U2.borrow().cm_e],
            },
            NovaCycleFoldCircuit {
                r: rho_bits.into(),
                points: vec![U1.borrow().cm_e, U2.borrow().cm_e * rho + proof],
            },
            NovaCycleFoldCircuit {
                r: rho_bits.into(),
                points: vec![U1.borrow().cm_w, U2.borrow().cm_w],
            },
        ]
    }

    #[allow(non_snake_case)]
    fn to_cyclefold_inputs(
        [U1, U2]: [<Self::Gadget as FoldingSchemeDefGadget>::RU; 2],
        _: [<Self::Gadget as FoldingSchemeDefGadget>::IU; 0],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<2, 0>,
        rho_bits: <Self::Gadget as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<Vec<Vec<EmulatedFieldVar<CM::Scalar, CF2<CM::Commitment>>>>, SynthesisError> {
        let mut rho_bits = rho_bits.to_vec();
        rho_bits.resize(
            CF2::<CM::Commitment>::MODULUS_BIT_SIZE as usize,
            Boolean::FALSE,
        );
        let rho = EmulatedFieldVar::from_bounded_bits_le(
            &rho_bits,
            Bounds(Zero::zero(), CF2::<CM::Commitment>::MODULUS.into().into()),
        )?;
        let cm_tmp_cs = U2.cm_e.cs().or(proof.cs()).or(rho_bits.cs());
        let cm_tmp = EmulatedAffineVar::new_witness(cm_tmp_cs.clone(), || {
            if cm_tmp_cs.is_in_setup_mode() {
                return Ok(Default::default());
            }
            let rho_bits = rho_bits.value()?;
            let rho = CM::Scalar::from_bits_le(&rho_bits);
            let proof_value = proof.value()?;
            let u2_value = U2.cm_e.value()?;
            Ok(proof_value + u2_value * rho)
        })?;
        Ok(vec![
            once(rho.clone())
                .chain(
                    [proof, U2.cm_e, cm_tmp.clone()]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(rho.clone())
                .chain(
                    [U1.cm_e, cm_tmp, UU.cm_e]
                        .into_iter()
                        .flat_map(|p| [p.x, p.y]),
                )
                .collect(),
            once(rho)
                .chain(
                    [U1.cm_w, U2.cm_w, UU.cm_w]
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
        rand::{RngCore, thread_rng},
        sync::Arc,
    };
    use sonobe_primitives::{
        circuits::{
            FCircuit,
            reciprocal_test::{NaiveReciprocalCircuitForTest, ReciprocalCircuitForTest},
            utils::CircuitForTest,
        },
        commitments::{CommitmentOps, pedersen::Pedersen},
        traits::Dummy,
        transcripts::griffin::{GriffinParams, sponge::GriffinSponge},
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{
        IVC,
        compilers::cyclefold::adapters::{
            reciprocal::{ReciprocalAdapterError, ReciprocalCycleFoldAdapter},
            reciprocal_bench::{
                BenchmarkSnapshotRow, benchmark_snapshot_rows, sample_naive_reciprocal_circuit,
                sample_reciprocal_circuit,
            },
            reciprocal_types::{
                ReciprocalSameQLane, ReciprocalTypeError, ReciprocalWitness,
                reciprocal_n4_trace_and_output,
            },
            reciprocal_wrapper::ReciprocalWrapperError,
        },
        tests::run_ivc_smoke_test,
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
