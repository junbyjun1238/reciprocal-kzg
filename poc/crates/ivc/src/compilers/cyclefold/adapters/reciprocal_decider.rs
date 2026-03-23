//! Minimal offchain decider helpers for the reciprocal PoC.

use ark_ff::PrimeField;
use sonobe_primitives::commitments::{CommitmentDef, CommitmentOps};
use thiserror::Error;

use super::{
    reciprocal::{
        ReciprocalAdapterError, ReciprocalCycleFoldAdapter, ReciprocalCycleFoldStatement,
    },
    reciprocal_types::{RECIPROCAL_N4_INPUT_LEN, ReciprocalSameQLane, ReciprocalTypeError},
};

/// [`ReciprocalOffchainDecision`] summarizes the reciprocal statement accepted
/// by the current offchain PoC verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalOffchainDecision {
    /// Descriptor length accepted by the decider.
    pub q_len: usize,
    /// Number of wrapped reciprocal coordinates carried by the proof object.
    pub coordinate_count: usize,
    /// Flattened public-input width of the accepted statement.
    pub public_input_len: usize,
    /// Whether the accepted statement carried an opening witness.
    pub has_opening_witness: bool,
}

/// [`ReciprocalOffchainDeciderError`] enumerates failures returned by the
/// reciprocal PoC's minimal offchain decider.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalOffchainDeciderError {
    /// The statement shape does not match the worked `N=4` reciprocal PoC.
    #[error(transparent)]
    Type(#[from] ReciprocalTypeError),
    /// The statement failed reciprocal adapter verification.
    #[error(transparent)]
    Adapter(#[from] ReciprocalAdapterError),
}

/// [`ReciprocalOffchainDecider`] provides a single entry point that checks the
/// current reciprocal PoC statement shape, lane policy, and optional opening
/// relation.
#[derive(Clone, Debug, Default)]
pub struct ReciprocalOffchainDecider;

impl ReciprocalOffchainDecider {
    /// Verifies a reciprocal statement under the selected same-`q` lane and
    /// returns a small summary on success.
    pub fn decide<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<ReciprocalOffchainDecision, ReciprocalOffchainDeciderError>
    where
        CM::Scalar: PrimeField,
    {
        Self::check_worked_n4_shape(statement)?;
        ReciprocalCycleFoldAdapter::verify_statement_in_lane(lane, statement)?;
        Ok(Self::summarize(statement))
    }

    /// Verifies an opening-aware reciprocal statement under the selected
    /// same-`q` lane and commitment key, then returns a small summary.
    pub fn decide_opening<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<ReciprocalOffchainDecision, ReciprocalOffchainDeciderError>
    where
        CM::Scalar: PrimeField,
    {
        Self::check_worked_n4_shape(statement)?;
        ReciprocalCycleFoldAdapter::verify_opening_statement_in_lane(ck, lane, statement)?;
        Ok(Self::summarize(statement))
    }

    fn check_worked_n4_shape<CM: CommitmentDef>(
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> Result<(), ReciprocalOffchainDeciderError> {
        let q_len = statement.instance.q.len();
        if q_len != RECIPROCAL_N4_INPUT_LEN {
            return Err(ReciprocalTypeError::DescriptorLengthMismatch {
                expected: RECIPROCAL_N4_INPUT_LEN,
                actual: q_len,
            }
            .into());
        }
        Ok(())
    }

    fn summarize<CM: CommitmentDef>(
        statement: &ReciprocalCycleFoldStatement<CM>,
    ) -> ReciprocalOffchainDecision {
        ReciprocalOffchainDecision {
            q_len: statement.instance.q.len(),
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
        reciprocal::ReciprocalCycleFoldAdapter,
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
        let lane = ReciprocalSameQLane::<TestCM>::new(q.clone());
        let ck = TestCM::generate_key(x.len(), &mut rng).expect("commitment key generation should work");
        let (cm_x, omega) =
            TestCM::commit(&ck, &x, &mut rng).expect("commitment generation should work");
        let (trace, y) =
            reciprocal_n4_trace_and_output(&q, &x).expect("worked reciprocal evaluator should work");
        (
            ck,
            lane.clone(),
            lane.bind(cm_x, y),
            ReciprocalWitness { x, trace, omega },
        )
    }

    #[test]
    fn test_reciprocal_offchain_decider_accepts_valid_opening_statement() {
        let (ck, lane, instance, witness) = sample_opening_bundle();
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck,
            &lane,
            &instance,
            witness,
        )
        .expect("opening statement construction should work");

        assert_eq!(
            ReciprocalOffchainDecider::decide_opening(&ck, &lane, &statement).expect("decider should accept the statement"),
            super::ReciprocalOffchainDecision {
                q_len: RECIPROCAL_N4_INPUT_LEN,
                coordinate_count: 4,
                public_input_len: statement.public_input_len(),
                has_opening_witness: true,
            }
        );
    }

    #[test]
    fn test_reciprocal_offchain_decider_rejects_descriptor_shape_mismatch() {
        let lane = ReciprocalSameQLane::<TestCM>::new(vec![1_u64.into(), 2_u64.into(), 3_u64.into()]);
        let instance = lane.bind(Default::default(), [10_u64.into(), 11_u64.into(), 12_u64.into(), 13_u64.into()]);
        let statement = ReciprocalCycleFoldAdapter::build_statement_in_lane(&lane, &instance)
            .expect("adapter statement construction should still work for same-q toy data");

        assert_eq!(
            ReciprocalOffchainDecider::decide(&lane, &statement),
            Err(ReciprocalOffchainDeciderError::Type(
                ReciprocalTypeError::DescriptorLengthMismatch {
                    expected: RECIPROCAL_N4_INPUT_LEN,
                    actual: 3,
                }
            ))
        );
    }

    #[test]
    fn test_reciprocal_offchain_decider_rejects_wrong_lane() {
        let (ck, lane, instance, witness) = sample_opening_bundle();
        let statement = ReciprocalCycleFoldAdapter::build_opening_statement_in_lane(
            &ck,
            &lane,
            &instance,
            witness,
        )
        .expect("opening statement construction should work");
        let wrong_lane =
            ReciprocalSameQLane::<TestCM>::new(vec![9_u64.into(), 9_u64.into(), 9_u64.into(), 9_u64.into()]);

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
