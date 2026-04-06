use ark_ff::PrimeField;
use thiserror::Error;

use super::{
    reciprocal_types::{
        ReciprocalPublicInstance, ReciprocalSameQLane, ReciprocalTypeError, ReciprocalWitness,
        check_worked_n4_instance,
    },
    reciprocal_wrapper::{ReciprocalAggregatedProof, ReciprocalWrapper, ReciprocalWrapperError},
};
use sonobe_primitives::{
    commitments::{CommitmentDef, CommitmentOps},
    transcripts::Absorbable,
};

const INSTANCE_DOMAIN_TAG: u64 = 0x5250_4955;
const PROOF_DOMAIN_TAG: u64 = 0x5250_5052;
const STATEMENT_DOMAIN_TAG: u64 = 0x5250_5354;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalCycleFoldStatement<CM: CommitmentDef> {
    pub instance: ReciprocalPublicInstance<CM>,
    pub proof: ReciprocalAggregatedProof<CM>,
    pub public_inputs: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> ReciprocalCycleFoldStatement<CM> {
    pub fn public_input_len(&self) -> usize {
        self.public_inputs.len()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalAdapterError {
    #[error(transparent)]
    Type(#[from] ReciprocalTypeError),
    #[error(transparent)]
    Wrapper(#[from] ReciprocalWrapperError),
    #[error("statement public inputs do not match the reciprocal instance/proof payload")]
    PublicInputMismatch,
}

#[derive(Clone, Debug, Default)]
pub struct ReciprocalCycleFoldAdapter;

impl ReciprocalCycleFoldAdapter {
    pub fn wrap_in_lane<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
    ) -> Result<ReciprocalAggregatedProof<CM>, ReciprocalAdapterError> {
        ReciprocalWrapper::aggregate_in_lane(lane, instance, ReciprocalWrapper::decompose(instance))
            .map_err(Self::normalize_lane_error)
    }

    pub fn wrap_opening_in_lane<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        witness: ReciprocalWitness<CM>,
    ) -> Result<ReciprocalAggregatedProof<CM>, ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalWrapper::prove_opening_in_lane(ck, lane, instance, witness)
            .map_err(Self::normalize_lane_error)
    }

    pub fn instance_public_inputs<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
    ) -> Vec<CM::Scalar>
    where
        CM::Scalar: PrimeField,
    {
        let mut public_inputs = Vec::new();
        public_inputs.push(Self::scalar_from_u64::<CM>(INSTANCE_DOMAIN_TAG));
        public_inputs.push(Self::scalar_from_u64::<CM>(instance.q.len() as u64));
        instance.q.absorb_into(&mut public_inputs);
        instance.y.absorb_into(&mut public_inputs);
        instance.cm_x.absorb_into(&mut public_inputs);
        public_inputs
    }

    pub fn proof_public_inputs<CM: CommitmentDef>(
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Vec<CM::Scalar>
    where
        CM::Scalar: PrimeField,
    {
        let mut public_inputs = Vec::new();
        public_inputs.push(Self::scalar_from_u64::<CM>(PROOF_DOMAIN_TAG));
        public_inputs.push(Self::scalar_from_u64::<CM>(proof.coordinates.len() as u64));

        for claim in &proof.coordinates {
            public_inputs.push(Self::scalar_from_u64::<CM>(claim.coordinate as u64));
            public_inputs.push(Self::scalar_from_u64::<CM>(claim.q.len() as u64));
            claim.q.absorb_into(&mut public_inputs);
            claim.value.absorb_into(&mut public_inputs);
            claim.cm_x.absorb_into(&mut public_inputs);
        }

        public_inputs
    }

    pub fn to_public_inputs<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<Vec<CM::Scalar>, ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        check_worked_n4_instance(instance)?;
        ReciprocalWrapper::verify(instance, proof)?;
        Ok(Self::flatten_public_inputs(instance, proof))
    }

    pub fn to_public_inputs_in_lane<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<Vec<CM::Scalar>, ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalWrapper::verify_in_lane(lane, instance, proof)
            .map_err(Self::normalize_lane_error)?;
        Ok(Self::flatten_public_inputs(instance, proof))
    }

    pub fn build_statement_in_lane<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
    ) -> Result<ReciprocalCycleFoldStatement<CM>, ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        let proof = Self::wrap_in_lane(lane, instance)?;
        let public_inputs = Self::flatten_public_inputs(instance, &proof);
        Ok(ReciprocalCycleFoldStatement {
            instance: instance.clone(),
            proof,
            public_inputs,
        })
    }

    pub fn build_opening_statement_in_lane<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        witness: ReciprocalWitness<CM>,
    ) -> Result<ReciprocalCycleFoldStatement<CM>, ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        let proof = Self::wrap_opening_in_lane(ck, lane, instance, witness)?;
        let public_inputs = Self::flatten_public_inputs(instance, &proof);
        Ok(ReciprocalCycleFoldStatement {
            instance: instance.clone(),
            proof,
            public_inputs,
        })
    }

    pub fn verify_statement<CM: CommitmentDef>(
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<(), ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalWrapper::verify(&statement.instance, &statement.proof)?;
        Self::ensure_public_inputs_match(
            &statement.instance,
            &statement.proof,
            &statement.public_inputs,
        )
    }

    pub fn verify_opening_statement<CM: CommitmentOps>(
        ck: &CM::Key,
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<(), ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalWrapper::verify_opening(ck, &statement.instance, &statement.proof)?;
        Self::ensure_public_inputs_match(
            &statement.instance,
            &statement.proof,
            &statement.public_inputs,
        )
    }

    pub fn verify_statement_in_lane<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<(), ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalWrapper::verify_in_lane(lane, &statement.instance, &statement.proof)
            .map_err(Self::normalize_lane_error)?;
        Self::ensure_public_inputs_match(
            &statement.instance,
            &statement.proof,
            &statement.public_inputs,
        )
    }

    pub fn verify_opening_statement_in_lane<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<(), ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalWrapper::verify_opening_in_lane(ck, lane, &statement.instance, &statement.proof)
            .map_err(Self::normalize_lane_error)?;
        Self::ensure_public_inputs_match(
            &statement.instance,
            &statement.proof,
            &statement.public_inputs,
        )
    }

    fn flatten_public_inputs<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Vec<CM::Scalar>
    where
        CM::Scalar: PrimeField,
    {
        let instance_public_inputs = Self::instance_public_inputs(instance);
        let proof_public_inputs = Self::proof_public_inputs(proof);

        let mut public_inputs =
            Vec::with_capacity(3 + instance_public_inputs.len() + proof_public_inputs.len());
        public_inputs.push(Self::scalar_from_u64::<CM>(STATEMENT_DOMAIN_TAG));
        public_inputs.push(Self::scalar_from_u64::<CM>(
            instance_public_inputs.len() as u64
        ));
        public_inputs.extend(instance_public_inputs);
        public_inputs.push(Self::scalar_from_u64::<CM>(proof_public_inputs.len() as u64));
        public_inputs.extend(proof_public_inputs);
        public_inputs
    }

    fn ensure_public_inputs_match<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
        public_inputs: &[CM::Scalar],
    ) -> Result<(), ReciprocalAdapterError>
    where
        CM::Scalar: PrimeField,
    {
        if public_inputs != Self::flatten_public_inputs(instance, proof) {
            return Err(ReciprocalAdapterError::PublicInputMismatch);
        }
        Ok(())
    }

    fn normalize_lane_error(err: ReciprocalWrapperError) -> ReciprocalAdapterError {
        match err {
            ReciprocalWrapperError::Type(type_err) => type_err.into(),
            ReciprocalWrapperError::DescriptorMismatch => {
                ReciprocalTypeError::DescriptorMismatch.into()
            }
            other => other.into(),
        }
    }

    fn scalar_from_u64<CM: CommitmentDef>(value: u64) -> CM::Scalar
    where
        CM::Scalar: PrimeField,
    {
        CM::Scalar::from_le_bytes_mod_order(&value.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use ark_ff::PrimeField;
    use ark_std::rand::thread_rng;
    use sonobe_primitives::{
        commitments::{CommitmentDef, CommitmentOps, pedersen::Pedersen},
        transcripts::Absorbable,
    };

    use super::{
        INSTANCE_DOMAIN_TAG, PROOF_DOMAIN_TAG, ReciprocalAdapterError, ReciprocalCycleFoldAdapter,
        STATEMENT_DOMAIN_TAG,
    };
    use crate::compilers::cyclefold::adapters::{
        reciprocal_types::{
            ReciprocalPublicInstance, ReciprocalSameQLane, ReciprocalWitness,
            reciprocal_n4_trace_and_output,
        },
        reciprocal_wrapper::{
            ReciprocalAggregatedProof, ReciprocalWrapper, ReciprocalWrapperError,
        },
    };

    type TestCM = Pedersen<G1Projective, true>;

    fn sample_instance() -> ReciprocalPublicInstance<TestCM> {
        ReciprocalPublicInstance {
            cm_x: Default::default(),
            q: vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()],
            y: [10_u64.into(), 11_u64.into(), 12_u64.into(), 13_u64.into()],
        }
    }

    fn sample_opening_bundle() -> (
        <TestCM as CommitmentDef>::Key,
        ReciprocalPublicInstance<TestCM>,
        ReciprocalWitness<TestCM>,
    ) {
        let mut rng = thread_rng();
        let x = vec![5_u64.into(), 6_u64.into(), 7_u64.into(), 8_u64.into()];
        let q = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let ck =
            TestCM::generate_key(x.len(), &mut rng).expect("commitment key generation should work");
        let (cm_x, omega) =
            TestCM::commit(&ck, &x, &mut rng).expect("commitment generation should work");
        let (trace, y) = reciprocal_n4_trace_and_output(&q, &x)
            .expect("worked reciprocal evaluator should work");
        (
            ck,
            ReciprocalPublicInstance { cm_x, q, y },
            ReciprocalWitness { x, trace, omega },
        )
    }

    #[test]
    fn test_reciprocal_adapter_flattens_instance_with_length_prefix() {
        let instance = sample_instance();
        let public_inputs = ReciprocalCycleFoldAdapter::instance_public_inputs(&instance);
        let mut expected = vec![
            <TestCM as CommitmentDef>::Scalar::from_le_bytes_mod_order(
                &INSTANCE_DOMAIN_TAG.to_le_bytes(),
            ),
            <TestCM as CommitmentDef>::Scalar::from_le_bytes_mod_order(
                &(instance.q.len() as u64).to_le_bytes(),
            ),
        ];
        instance.q.absorb_into(&mut expected);
        instance.y.absorb_into(&mut expected);
        instance.cm_x.absorb_into(&mut expected);

        assert_eq!(public_inputs, expected);
    }

    #[test]
    fn test_reciprocal_adapter_flattens_proof_with_coordinate_prefixes() {
        let instance = sample_instance();
        let proof =
            ReciprocalWrapper::aggregate(&instance, ReciprocalWrapper::decompose(&instance))
                .expect("wrapper should accept consistent reciprocal coordinates");
        let public_inputs = ReciprocalCycleFoldAdapter::proof_public_inputs(&proof);

        assert_eq!(
            public_inputs[0],
            <TestCM as CommitmentDef>::Scalar::from_le_bytes_mod_order(
                &PROOF_DOMAIN_TAG.to_le_bytes()
            )
        );
        assert_eq!(public_inputs[1], 4_u64.into());
        assert!(public_inputs.len() > 2 + 4);
    }

    #[test]
    fn test_reciprocal_adapter_to_public_inputs_rejects_invalid_wrapper_proof() {
        let instance = sample_instance();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[0].value = 99_u64.into();
        let proof = ReciprocalAggregatedProof {
            coordinates,
            opening_witness: None,
        };

        assert_eq!(
            ReciprocalCycleFoldAdapter::to_public_inputs(&instance, &proof),
            Err(ReciprocalAdapterError::Wrapper(
                ReciprocalWrapperError::OutputMismatch { coordinate: 0 }
            ))
        );
    }

    #[test]
    fn test_reciprocal_adapter_to_public_inputs_in_lane_rejects_descriptor_mismatch() {
        let instance = sample_instance();
        let proof =
            ReciprocalWrapper::aggregate(&instance, ReciprocalWrapper::decompose(&instance))
                .expect("wrapper should accept consistent reciprocal coordinates");
        let wrong_lane = ReciprocalSameQLane::<TestCM>::new(vec![
            9_u64.into(),
            9_u64.into(),
            9_u64.into(),
            9_u64.into(),
        ])
        .expect("worked N=4 descriptor should define a valid lane");

        assert_eq!(
            ReciprocalCycleFoldAdapter::to_public_inputs_in_lane(&wrong_lane, &instance, &proof),
            Err(ReciprocalAdapterError::Type(
                super::ReciprocalTypeError::DescriptorMismatch
            ))
        );
    }

    #[test]
    fn test_reciprocal_adapter_build_statement_in_lane() {
        let instance = sample_instance();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.q.clone())
            .expect("worked instance should define a valid same-q lane");
        let statement = ReciprocalCycleFoldAdapter::build_statement_in_lane(&lane, &instance)
            .expect("same-q lane should accept the statement");

        assert_eq!(statement.instance, instance);
        assert_eq!(statement.proof.coordinates.len(), 4);
        assert_eq!(
            statement.public_inputs[0],
            <TestCM as CommitmentDef>::Scalar::from_le_bytes_mod_order(
                &STATEMENT_DOMAIN_TAG.to_le_bytes()
            )
        );
        assert_eq!(statement.public_input_len(), statement.public_inputs.len());
    }

    #[test]
    fn test_reciprocal_adapter_verify_statement_in_lane_accepts_valid_statement() {
        let instance = sample_instance();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.q.clone())
            .expect("worked instance should define a valid same-q lane");
        let statement = ReciprocalCycleFoldAdapter::build_statement_in_lane(&lane, &instance)
            .expect("same-q lane should accept the statement");

        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_statement_in_lane(&lane, &statement),
            Ok(())
        );
    }

    #[test]
    fn test_reciprocal_adapter_verify_statement_in_lane_rejects_tampered_output() {
        let instance = sample_instance();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.q.clone())
            .expect("worked instance should define a valid same-q lane");
        let mut statement = ReciprocalCycleFoldAdapter::build_statement_in_lane(&lane, &instance)
            .expect("same-q lane should accept the statement");
        statement.instance.y[0] = 99_u64.into();

        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_statement_in_lane(&lane, &statement),
            Err(ReciprocalAdapterError::Wrapper(
                ReciprocalWrapperError::OutputMismatch { coordinate: 0 }
            ))
        );
    }

    #[test]
    fn test_reciprocal_adapter_verify_statement_rejects_public_input_mismatch() {
        let instance = sample_instance();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.q.clone())
            .expect("worked instance should define a valid same-q lane");
        let mut statement = ReciprocalCycleFoldAdapter::build_statement_in_lane(&lane, &instance)
            .expect("same-q lane should accept the statement");
        statement.public_inputs[0] = 0_u64.into();

        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_statement(&statement),
            Err(ReciprocalAdapterError::PublicInputMismatch)
        );
    }

    #[test]
    fn test_reciprocal_adapter_build_opening_statement_in_lane() {
        let (ck, instance, witness) = sample_opening_bundle();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.q.clone())
            .expect("worked instance should define a valid same-q lane");
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, &lane, &instance, witness,
        )
        .expect("opening statement construction should work");

        assert!(statement.proof.opening_witness.is_some());
        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(&ck, &lane, &statement),
            Ok(())
        );
    }

    #[test]
    fn test_reciprocal_adapter_verify_opening_statement_rejects_public_input_mismatch() {
        let (ck, instance, witness) = sample_opening_bundle();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.q.clone())
            .expect("worked instance should define a valid same-q lane");
        let mut statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, &lane, &instance, witness,
        )
        .expect("opening statement construction should work");
        statement.public_inputs[0] = 0_u64.into();

        assert_eq!(
            ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(&ck, &lane, &statement),
            Err(ReciprocalAdapterError::PublicInputMismatch)
        );
    }
}
