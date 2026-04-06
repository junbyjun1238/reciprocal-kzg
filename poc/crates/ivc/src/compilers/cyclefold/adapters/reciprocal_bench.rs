use std::time::Instant;

use ark_bn254::{Fr, G1Projective as C1};
use ark_grumpkin::Projective as C2;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_std::{rand::thread_rng, sync::Arc};
use sonobe_fs::DeciderKey;
use sonobe_primitives::{
    arithmetizations::{Arith, ArithConfig, r1cs::R1CS},
    circuits::{
        ArithExtractor, FCircuit,
        reciprocal_test::{
            NaiveReciprocalCircuitForTest, ReciprocalCircuitForTest, ReciprocalDescriptorError,
            ReciprocalSeedDescriptorN4,
        },
        utils::CircuitForTest,
    },
    commitments::{CommitmentOps, Error as CommitmentError, pedersen::Pedersen},
    traits::Dummy,
    transcripts::griffin::{GriffinParams, sponge::GriffinSponge},
};
use thiserror::Error;

use crate::{
    Error as IvcError, IVC,
    compilers::cyclefold::{
        Key,
        adapters::{
            nova::NovaNovaIVC,
            reciprocal::{ReciprocalAdapterError, ReciprocalCycleFoldAdapter},
            reciprocal_decider::{ReciprocalOffchainDecider, ReciprocalOffchainDeciderError},
            reciprocal_types::{
                ReciprocalSameQLane, ReciprocalTypeError, ReciprocalWitness,
                reciprocal_n4_trace_and_output,
            },
        },
    },
};

#[derive(Debug, Error)]
pub enum ReciprocalBenchmarkError {
    #[error(transparent)]
    Descriptor(#[from] ReciprocalDescriptorError),
    #[error(transparent)]
    Type(#[from] ReciprocalTypeError),
    #[error(transparent)]
    Commitment(#[from] CommitmentError),
    #[error(transparent)]
    Adapter(#[from] ReciprocalAdapterError),
    #[error(transparent)]
    Decider(#[from] ReciprocalOffchainDeciderError),
    #[error(transparent)]
    Ivc(#[from] IvcError),
}

type ReciprocalBenchmarkResult<T> = Result<T, ReciprocalBenchmarkError>;

#[derive(Clone, Debug)]
pub struct BenchmarkSnapshotRow {
    pub name: &'static str,
    pub steps: usize,
    pub state_width: usize,
    pub step_constraints: usize,
    pub step_public_inputs: usize,
    pub step_witnesses: usize,
    pub primary_constraints: usize,
    pub secondary_constraints: usize,
    pub preprocess_ms: u128,
    pub keygen_ms: u128,
    pub avg_prove_ms: u128,
    pub avg_verify_ms: u128,
    pub external_output_width: usize,
    pub q_len: usize,
    pub adapter_public_inputs: usize,
}

impl BenchmarkSnapshotRow {
    pub fn csv_header() -> &'static str {
        "name,steps,state_width,step_constraints,step_public_inputs,step_witnesses,primary_constraints,secondary_constraints,preprocess_ms,keygen_ms,avg_prove_ms,avg_verify_ms,external_output_width,q_len,adapter_public_inputs"
    }

    pub fn csv_row(&self) -> String {
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

type ReciprocalBenchmarkIVC =
    NovaNovaIVC<Pedersen<C1, true>, Pedersen<C2, true>, GriffinSponge<Fr>>;

pub fn sample_seed_descriptor() -> ReciprocalSeedDescriptorN4<Fr> {
    ReciprocalSeedDescriptorN4::new([
        Fr::from(1_u64),
        -Fr::from(4_u64),
        -Fr::from(3_u64),
        -Fr::from(2_u64),
    ])
}

pub fn sample_leaf_offsets() -> [Fr; 4] {
    [
        Fr::from(0_u64),
        Fr::from(1_u64),
        Fr::from(2_u64),
        Fr::from(3_u64),
    ]
}

pub fn sample_reciprocal_circuit() -> ReciprocalBenchmarkResult<ReciprocalCircuitForTest<Fr>> {
    Ok(ReciprocalCircuitForTest::from_seed_descriptor(
        sample_seed_descriptor(),
        sample_leaf_offsets(),
    )?)
}

pub fn sample_naive_reciprocal_circuit()
-> ReciprocalBenchmarkResult<NaiveReciprocalCircuitForTest<Fr>> {
    Ok(NaiveReciprocalCircuitForTest::from_seed_descriptor(
        sample_seed_descriptor(),
        sample_leaf_offsets(),
    )?)
}

fn extract_step_r1cs_config<FC>(step_circuit: &FC) -> Result<(usize, usize, usize), IvcError>
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

pub fn benchmark_nova_nova_circuit<FC>(
    name: &'static str,
    step_circuit: &FC,
    steps: usize,
    state_width: usize,
    external_output_width: usize,
) -> ReciprocalBenchmarkResult<BenchmarkSnapshotRow>
where
    FC: FCircuit<Field = Fr, ExternalInputs = ()>,
{
    let (step_constraints, step_public_inputs, step_witnesses) =
        extract_step_r1cs_config(step_circuit)?;

    let mut rng = thread_rng();
    let preprocess_start = Instant::now();
    let pp = ReciprocalBenchmarkIVC::preprocess(
        (65536, 2048, Arc::new(GriffinParams::new(16, 5, 9))),
        &mut rng,
    )?;
    let preprocess_ms = preprocess_start.elapsed().as_millis();

    let keygen_start = Instant::now();
    let (pk, vk) = ReciprocalBenchmarkIVC::generate_keys(pp, step_circuit)?;
    let keygen_ms = keygen_start.elapsed().as_millis();

    let Key(dk1, dk2, _) = &pk;
    let primary_constraints = <_ as DeciderKey>::to_arith_config(dk1).n_constraints();
    let secondary_constraints = <_ as DeciderKey>::to_arith_config(dk2).n_constraints();

    let initial_state = step_circuit.dummy_state();
    let mut current_state = initial_state.clone();
    let mut current_proof = <ReciprocalBenchmarkIVC as IVC>::Proof::<FC>::dummy(&pk);

    let mut total_prove_ms = 0_u128;
    let mut total_verify_ms = 0_u128;

    for step in 0..steps {
        let prove_start = Instant::now();
        let (next_state, _external_outputs, next_proof) = ReciprocalBenchmarkIVC::prove(
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
        ReciprocalBenchmarkIVC::verify::<FC>(
            &vk,
            step + 1,
            &initial_state,
            &next_state,
            &next_proof,
        )?;
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

pub fn reciprocal_adapter_public_input_len(
    circuit: &ReciprocalCircuitForTest<Fr>,
) -> ReciprocalBenchmarkResult<usize> {
    let mut rng = thread_rng();
    let lane = ReciprocalSameQLane::<Pedersen<C1, true>>::new(circuit.q.to_vec())?;
    let x = circuit.leaf_vector(Fr::from(0_u64)).to_vec();
    let ck = Pedersen::<C1, true>::generate_key(x.len(), &mut rng)?;
    let (cm_x, omega) = Pedersen::<C1, true>::commit(&ck, &x, &mut rng)?;
    let (trace, y) = reciprocal_n4_trace_and_output(&circuit.q, &x)?;
    let instance = lane.bind(cm_x, y);
    let witness = ReciprocalWitness::<Pedersen<C1, true>> { x, trace, omega };
    let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
        &ck, &lane, &instance, witness,
    )?;
    Ok(ReciprocalOffchainDecider::decide_opening(&ck, &lane, &statement)?.public_input_len)
}

pub fn benchmark_snapshot_rows() -> ReciprocalBenchmarkResult<[BenchmarkSnapshotRow; 3]> {
    let naive_reciprocal_circuit = sample_naive_reciprocal_circuit()?;
    let reciprocal_circuit = sample_reciprocal_circuit()?;

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

    stock_row.q_len = 0;
    stock_row.adapter_public_inputs = 0;

    naive_row.q_len = naive_reciprocal_circuit.q.len();
    naive_row.adapter_public_inputs = 0;

    reciprocal_row.q_len = reciprocal_circuit.q.len();
    reciprocal_row.adapter_public_inputs =
        reciprocal_adapter_public_input_len(&reciprocal_circuit)?;

    Ok([stock_row, naive_row, reciprocal_row])
}
