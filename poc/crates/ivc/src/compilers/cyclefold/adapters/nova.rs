//! Nova CycleFold adapter that bridges Nova into the CycleFold IVC compiler.

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

/// [`NovaCycleFoldCircuit`] defines CycleFold circuit for Nova.
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
    fn verify_point_rlc(&self, cs: ConstraintSystemRef<CF2<C>>) -> Result<(), SynthesisError> {
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

/// [`NovaNovaIVC`] defines a CycleFold-based IVC using Nova as the primary
/// folding scheme and Nova as the secondary folding scheme.
pub type NovaNovaIVC<VC1, VC2, T, const CHALLENGE_BITS: usize = 128> =
    CycleFoldBasedIVC<Nova<VC1, CHALLENGE_BITS>, CycleFoldNova<VC2, CHALLENGE_BITS>, T>;

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ark_bn254::{Fr, G1Projective as C1};
    use ark_ff::UniformRand;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_grumpkin::Projective as C2;
    use ark_std::{error::Error, rand::thread_rng, sync::Arc};
    use sonobe_fs::DeciderKey;
    use sonobe_primitives::{
        arithmetizations::{Arith, ArithConfig, r1cs::R1CS},
        circuits::{
            ArithExtractor, FCircuit,
            reciprocal_test::{
                NaiveReciprocalCircuitForTest, ReciprocalCircuitForTest,
                ReciprocalSeedDescriptorN4,
            },
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
        compilers::cyclefold::{
            Key,
            adapters::{
                reciprocal::{ReciprocalAdapterError, ReciprocalCycleFoldAdapter},
                reciprocal_types::{
                    ReciprocalSameQLane, ReciprocalTypeError, ReciprocalWitness,
                    reciprocal_n4_trace_and_output,
                },
                reciprocal_wrapper::ReciprocalWrapperError,
            },
        },
        tests::test_ivc,
    };

    #[derive(Clone, Debug)]
    struct BenchmarkSnapshotRow {
        name: &'static str,
        steps: usize,
        state_width: usize,
        step_constraints: usize,
        step_public_inputs: usize,
        step_witnesses: usize,
        primary_constraints: usize,
        secondary_constraints: usize,
        preprocess_ms: u128,
        keygen_ms: u128,
        avg_prove_ms: u128,
        avg_verify_ms: u128,
        external_output_width: usize,
        q_len: usize,
        adapter_public_inputs: usize,
    }

    impl BenchmarkSnapshotRow {
        fn csv_header() -> &'static str {
            "name,steps,state_width,step_constraints,step_public_inputs,step_witnesses,primary_constraints,secondary_constraints,preprocess_ms,keygen_ms,avg_prove_ms,avg_verify_ms,external_output_width,q_len,adapter_public_inputs"
        }

        fn csv_row(&self) -> String {
            format!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                self.name,
                self.steps,
                self.state_width,
                self.step_constraints,
                self.step_public_inputs,
                self.step_witnesses,
                self.primary_constraints,
                self.secondary_constraints,
                self.preprocess_ms,
                self.keygen_ms,
                self.avg_prove_ms,
                self.avg_verify_ms,
                self.external_output_width,
                self.q_len,
                self.adapter_public_inputs,
            )
        }
    }

    fn sample_seed_descriptor() -> ReciprocalSeedDescriptorN4<Fr> {
        ReciprocalSeedDescriptorN4::new([
            Fr::from(1_u64),
            -Fr::from(4_u64),
            -Fr::from(3_u64),
            -Fr::from(2_u64),
        ])
    }

    fn sample_leaf_offsets() -> [Fr; 4] {
        [Fr::from(0_u64), Fr::from(1_u64), Fr::from(2_u64), Fr::from(3_u64)]
    }

    fn sample_reciprocal_circuit() -> ReciprocalCircuitForTest<Fr> {
        ReciprocalCircuitForTest::from_seed_descriptor(
            sample_seed_descriptor(),
            sample_leaf_offsets(),
        )
        .expect("sample seed descriptor should expand")
    }

    fn sample_naive_reciprocal_circuit() -> NaiveReciprocalCircuitForTest<Fr> {
        NaiveReciprocalCircuitForTest::from_seed_descriptor(
            sample_seed_descriptor(),
            sample_leaf_offsets(),
        )
        .expect("sample seed descriptor should expand")
    }

    fn extract_step_r1cs_config<FC>(step_circuit: &FC) -> Result<(usize, usize, usize), Box<dyn Error>>
    where
        FC: FCircuit<Field = Fr, ExternalInputs = ()>,
    {
        let cs = ArithExtractor::<Fr>::new();
        cs.execute_fn(|cs| {
            let i = FpVar::new_witness(cs.clone(), || Ok(Fr::from(0_u64)))?;
            let state = <FC::StateVar as AllocVar<FC::State, Fr>>::new_witness(cs, || {
                Ok(step_circuit.dummy_state())
            })?;
            let _ = step_circuit.generate_step_constraints(
                i,
                state,
                step_circuit.dummy_external_inputs(),
            )?;
            Ok(())
        })?;
        let arith = cs.arith::<R1CS<Fr>>()?;
        let cfg = arith.config();
        Ok((
            cfg.n_constraints(),
            cfg.n_public_inputs(),
            cfg.n_witnesses(),
        ))
    }

    fn benchmark_nova_nova_circuit<FC>(
        name: &'static str,
        step_circuit: &FC,
        steps: usize,
        state_width: usize,
        external_output_width: usize,
    ) -> Result<BenchmarkSnapshotRow, Box<dyn Error>>
    where
        FC: FCircuit<Field = Fr, ExternalInputs = ()>,
    {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let (step_constraints, step_public_inputs, step_witnesses) =
            extract_step_r1cs_config(step_circuit)?;

        let mut rng = thread_rng();
        let preprocess_start = Instant::now();
        let pp = TestIVC::preprocess(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            &mut rng,
        )?;
        let preprocess_ms = preprocess_start.elapsed().as_millis();

        let keygen_start = Instant::now();
        let (pk, vk) = TestIVC::generate_keys(pp, step_circuit)?;
        let keygen_ms = keygen_start.elapsed().as_millis();

        let Key(dk1, dk2, _) = &pk;
        let primary_constraints = dk1.to_arith_config().n_constraints();
        let secondary_constraints = dk2.to_arith_config().n_constraints();

        let initial_state = step_circuit.dummy_state();
        let mut current_state = initial_state.clone();
        let mut current_proof = <TestIVC as IVC>::Proof::<FC>::dummy(&pk);

        let mut total_prove_ms = 0_u128;
        let mut total_verify_ms = 0_u128;

        for step in 0..steps {
            let prove_start = Instant::now();
            let (next_state, _external_outputs, next_proof) = TestIVC::prove(
                &pk,
                step_circuit,
                step,
                &initial_state,
                &current_state,
                (),
                &current_proof,
                &mut rng,
            )?;
            total_prove_ms += prove_start.elapsed().as_millis();

            let verify_start = Instant::now();
            TestIVC::verify::<FC>(&vk, step + 1, &initial_state, &next_state, &next_proof)?;
            total_verify_ms += verify_start.elapsed().as_millis();

            current_state = next_state;
            current_proof = next_proof;
        }

        Ok(BenchmarkSnapshotRow {
            name,
            steps,
            state_width,
            step_constraints,
            step_public_inputs,
            step_witnesses,
            primary_constraints,
            secondary_constraints,
            preprocess_ms,
            keygen_ms,
            avg_prove_ms: total_prove_ms / steps as u128,
            avg_verify_ms: total_verify_ms / steps as u128,
            external_output_width,
            q_len: 0,
            adapter_public_inputs: 0,
        })
    }

    fn reciprocal_adapter_public_input_len(
        circuit: &ReciprocalCircuitForTest<Fr>,
    ) -> Result<usize, Box<dyn Error>> {
        let mut rng = thread_rng();
        let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(circuit.q.to_vec());
        let x = circuit.leaf_vector(Fr::from(0_u64)).to_vec();
        let ck = <Pedersen<C1, true> as CommitmentOps>::generate_key(x.len(), &mut rng)?;
        let (cm_x, omega) = <Pedersen<C1, true> as CommitmentOps>::commit(&ck, &x, &mut rng)?;
        let (trace, y) = reciprocal_n4_trace_and_output(&lane.q().to_vec(), &x)?;
        let witness = ReciprocalWitness { x, trace, omega };
        let instance = lane.bind(cm_x, y);
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck,
            &lane,
            &instance,
            witness,
        )?;
        Ok(statement.public_input_len())
    }

    #[test]
    fn test_nova_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        test_ivc::<NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<_>>, _>(
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
    fn test_nova_nova_reciprocal_circuit_outputs() -> Result<(), Box<dyn Error>> {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let mut rng = thread_rng();
        let step_circuit = sample_reciprocal_circuit();
        let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(step_circuit.q.to_vec());

        let pp = TestIVC::preprocess(
            (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
            &mut rng,
        )?;
        let (pk, vk) = TestIVC::generate_keys(pp, &step_circuit)?;

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

            let leaf_vector = step_circuit.leaf_vector(current_state[0]).to_vec();
            let ck =
                <Pedersen<C1, true> as CommitmentOps>::generate_key(leaf_vector.len(), &mut rng)?;
            let (cm_x, omega) =
                <Pedersen<C1, true> as CommitmentOps>::commit(&ck, &leaf_vector, &mut rng)?;
            let (trace, expected_y) =
                reciprocal_n4_trace_and_output(&lane.q().to_vec(), &leaf_vector)?;
            assert_eq!(external_outputs, expected_y);
            let witness = ReciprocalWitness {
                x: leaf_vector,
                trace,
                omega,
            };
            let instance = lane.bind(cm_x, external_outputs);
            let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
                &ck, &lane, &instance, witness,
            )?;
            ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(&ck, &lane, &statement)?;

            current_state = next_state;
            current_proof = next_proof;
        }

        Ok(())
    }

    #[test]
    fn test_nova_nova_reciprocal_statement_rejects_tampered_output() -> Result<(), Box<dyn Error>> {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let mut rng = thread_rng();
        let step_circuit = sample_reciprocal_circuit();
        let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(step_circuit.q.to_vec());

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
        let ck =
            <Pedersen<C1, true> as CommitmentOps>::generate_key(leaf_vector.len(), &mut rng)?;
        let (cm_x, omega) =
            <Pedersen<C1, true> as CommitmentOps>::commit(&ck, &leaf_vector, &mut rng)?;
        let (trace, expected_y) = reciprocal_n4_trace_and_output(&lane.q().to_vec(), &leaf_vector)?;
        assert_eq!(external_outputs, expected_y);
        let witness = ReciprocalWitness {
            x: leaf_vector,
            trace,
            omega,
        };
        let instance = lane.bind(cm_x, external_outputs);
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
    fn test_nova_nova_reciprocal_statement_rejects_wrong_descriptor_lane() -> Result<(), Box<dyn Error>> {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let mut rng = thread_rng();
        let step_circuit = sample_reciprocal_circuit();
        let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(step_circuit.q.to_vec());
        let wrong_lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(vec![
            Fr::from(9_u64),
            Fr::from(9_u64),
            Fr::from(9_u64),
            Fr::from(9_u64),
        ]);

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
        let ck =
            <Pedersen<C1, true> as CommitmentOps>::generate_key(leaf_vector.len(), &mut rng)?;
        let (cm_x, omega) =
            <Pedersen<C1, true> as CommitmentOps>::commit(&ck, &leaf_vector, &mut rng)?;
        let (trace, expected_y) = reciprocal_n4_trace_and_output(&lane.q().to_vec(), &leaf_vector)?;
        assert_eq!(external_outputs, expected_y);
        let witness = ReciprocalWitness {
            x: leaf_vector,
            trace,
            omega,
        };
        let instance = lane.bind(cm_x, external_outputs);
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, &lane, &instance, witness,
        )?;

        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(&ck, &wrong_lane, &statement),
            Err(ReciprocalAdapterError::Type(
                ReciprocalTypeError::DescriptorMismatch
            ))
        );

        Ok(())
    }

    #[test]
    fn test_nova_nova_naive_reciprocal_circuit_outputs() -> Result<(), Box<dyn Error>> {
        type TestIVC = NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

        let mut rng = thread_rng();
        let step_circuit = sample_naive_reciprocal_circuit();

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
        // This snapshot is grant-facing rather than production-grade. The
        // stable comparison signals are state width, witnesses, constraints,
        // and reciprocal adapter public-input width; timing columns are only
        // rough local measurements.
        let naive_reciprocal_circuit = sample_naive_reciprocal_circuit();
        let reciprocal_circuit = sample_reciprocal_circuit();

        let mut stock_row = benchmark_nova_nova_circuit(
            "stock_circuit_for_test",
            &CircuitForTest { x: Fr::from(3_u64) },
            3,
            1,
            0,
        )?;

        let mut naive_row = benchmark_nova_nova_circuit(
            "naive_reciprocal_stateful_test",
            &naive_reciprocal_circuit,
            3,
            9,
            4,
        )?;
        let mut reciprocal_row =
            benchmark_nova_nova_circuit("reciprocal_same_q_test", &reciprocal_circuit, 3, 1, 4)?;
        naive_row.q_len = naive_reciprocal_circuit.q.len();
        naive_row.adapter_public_inputs = 0;
        reciprocal_row.q_len = reciprocal_circuit.q.len();
        reciprocal_row.adapter_public_inputs = reciprocal_adapter_public_input_len(&reciprocal_circuit)?;

        stock_row.q_len = 0;
        stock_row.adapter_public_inputs = 0;

        println!("{}", BenchmarkSnapshotRow::csv_header());
        println!("{}", stock_row.csv_row());
        println!("{}", naive_row.csv_row());
        println!("{}", reciprocal_row.csv_row());

        Ok(())
    }
}
