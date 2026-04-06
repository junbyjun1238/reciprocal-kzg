use ark_ff::PrimeField;
use sonobe_primitives::commitments::{CommitmentDef, CommitmentOps};
use thiserror::Error;

use super::{
    reciprocal::{
        ReciprocalAdapterError, ReciprocalCycleFoldAdapter, ReciprocalCycleFoldStatement,
    },
    reciprocal_types::{ReciprocalSameQLane, ReciprocalTypeError},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalOffchainDecision {
    pub q_len: usize,
    pub coordinate_count: usize,
    pub public_input_len: usize,
    pub has_opening_witness: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalOffchainDeciderError {
    #[error(transparent)]
    Type(#[from] ReciprocalTypeError),
    #[error(transparent)]
    Adapter(#[from] ReciprocalAdapterError),
}

#[derive(Clone, Debug, Default)]
pub struct ReciprocalOffchainDecider;

impl ReciprocalOffchainDecider {
    pub fn decide<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<ReciprocalOffchainDecision, ReciprocalOffchainDeciderError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalCycleFoldAdapter::verify_statement_in_lane(lane, statement)?;
        Ok(Self::summarize(statement))
    }

    pub fn decide_opening<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<ReciprocalOffchainDecision, ReciprocalOffchainDeciderError>
    where
        CM::Scalar: PrimeField,
    {
        ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(ck, lane, statement)?;
        Ok(Self::summarize(statement))
    }

    fn summarize<CM: CommitmentDef>(
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> ReciprocalOffchainDecision {
        ReciprocalOffchainDecision {
            q_len: statement.instance.descriptor.len(),
            coordinate_count: statement.proof.coordinates.len(),
            public_input_len: statement.public_input_len(),
            has_opening_witness: statement.proof.opening_witness.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use ark_std::rand::thread_rng;
    use sonobe_primitives::commitments::{CommitmentDef, CommitmentOps, pedersen::Pedersen};

    use super::{ReciprocalOffchainDecider, ReciprocalOffchainDeciderError};
    use crate::compilers::cyclefold::adapters::{
        reciprocal::{ReciprocalCycleFoldAdapter, ReciprocalCycleFoldStatement},
        reciprocal_types::{
            RECIPROCAL_N4_INPUT_LEN, ReciprocalPublicInstance, ReciprocalSameQLane,
            ReciprocalTypeError, ReciprocalWitness, reciprocal_n4_trace_and_output,
        },
    };

    type TestCM = Pedersen<G1Projective, true>;

    fn sample_opening_bundle() -> (
        <TestCM as CommitmentDef>::Key,
        ReciprocalSameQLane<TestCM>,
        ReciprocalPublicInstance<TestCM>,
        ReciprocalWitness<TestCM>,
    ) {
        let mut rng = thread_rng();
        let x = vec![5_u64.into(), 6_u64.into(), 7_u64.into(), 8_u64.into()];
        let q = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let lane = ReciprocalSameQLane::<TestCM>::new(q.clone())
            .expect("worked instance should define a valid same-q lane");
        let ck =
            TestCM::generate_key(x.len(), &mut rng).expect("commitment key generation should work");
        let (cm_x, omega) =
            TestCM::commit(&ck, &x, &mut rng).expect("commitment generation should work");
        let (trace, y) = reciprocal_n4_trace_and_output(&q, &x)
            .expect("worked reciprocal evaluator should work");
        (
            ck,
            lane.clone(),
            lane.bind_instance(cm_x, y),
            ReciprocalWitness { x, trace, omega },
        )
    }

    #[test]
    fn test_decider_accepts_valid_opening_statement() {
        let (ck, lane, instance, witness) = sample_opening_bundle();
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, &lane, &instance, witness,
        )
        .expect("opening statement construction should work");

        assert_eq!(
            ReciprocalOffchainDecider::decide_opening(&ck, &lane, &statement)
                .expect("decider should accept the statement"),
            super::ReciprocalOffchainDecision {
                q_len: RECIPROCAL_N4_INPUT_LEN,
                coordinate_count: 4,
                public_input_len: statement.public_input_len(),
                has_opening_witness: true,
            }
        );
    }

    #[test]
    fn test_decider_rejects_descriptor_shape_mismatch() {
        let lane = ReciprocalSameQLane::<TestCM>::new_unchecked(vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
        ]);
        let instance = lane.bind_instance(
            Default::default(),
            [10_u64.into(), 11_u64.into(), 12_u64.into(), 13_u64.into()],
        );
        let statement = ReciprocalCycleFoldStatement {
            instance,
            proof: super::super::reciprocal_wrapper::ReciprocalAggregatedProof {
                coordinates: [
                    super::super::reciprocal_wrapper::ReciprocalCoordinateClaim {
                        cm_x: Default::default(),
                        descriptor: vec![1_u64.into(), 2_u64.into(), 3_u64.into()],
                        coordinate: 0,
                        value: 10_u64.into(),
                    },
                    super::super::reciprocal_wrapper::ReciprocalCoordinateClaim {
                        cm_x: Default::default(),
                        descriptor: vec![1_u64.into(), 2_u64.into(), 3_u64.into()],
                        coordinate: 1,
                        value: 11_u64.into(),
                    },
                    super::super::reciprocal_wrapper::ReciprocalCoordinateClaim {
                        cm_x: Default::default(),
                        descriptor: vec![1_u64.into(), 2_u64.into(), 3_u64.into()],
                        coordinate: 2,
                        value: 12_u64.into(),
                    },
                    super::super::reciprocal_wrapper::ReciprocalCoordinateClaim {
                        cm_x: Default::default(),
                        descriptor: vec![1_u64.into(), 2_u64.into(), 3_u64.into()],
                        coordinate: 3,
                        value: 13_u64.into(),
                    },
                ],
                opening_witness: None,
            },
            public_inputs: Vec::new(),
        };

        assert_eq!(
            ReciprocalOffchainDecider::decide(&lane, &statement),
            Err(ReciprocalOffchainDeciderError::Adapter(
                super::super::reciprocal::ReciprocalAdapterError::Type(
                    ReciprocalTypeError::DescriptorLengthMismatch {
                        expected: RECIPROCAL_N4_INPUT_LEN,
                        actual: 3,
                    }
                )
            ))
        );
    }

    #[test]
    fn test_reciprocal_offchain_decider_rejects_wrong_lane() {
        let (ck, lane, instance, witness) = sample_opening_bundle();
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck, &lane, &instance, witness,
        )
        .expect("opening statement construction should work");
        let wrong_lane = ReciprocalSameQLane::<TestCM>::new(vec![
            9_u64.into(),
            9_u64.into(),
            9_u64.into(),
            9_u64.into(),
        ])
        .expect("worked instance should define a valid same-q lane");

        assert_eq!(
            ReciprocalOffchainDecider::decide_opening(&ck, &wrong_lane, &statement),
            Err(ReciprocalOffchainDeciderError::Adapter(
                super::super::reciprocal::ReciprocalAdapterError::Type(
                    ReciprocalTypeError::DescriptorMismatch
                )
            ))
        );
    }
}
