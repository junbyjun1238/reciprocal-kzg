use thiserror::Error;

use super::reciprocal_types::{
    RECIPROCAL_N4_TRACE_LEN, ReciprocalPublicInstance, ReciprocalSameQLane, ReciprocalTypeError,
    ReciprocalWitness, reciprocal_n4_trace_and_output,
};
use ark_ff::PrimeField;
use sonobe_primitives::commitments::{CommitmentDef, CommitmentOps};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalCoordinateClaim<CM: CommitmentDef> {
    pub cm_x: CM::Commitment,
    pub descriptor: Vec<CM::Scalar>,
    pub coordinate: usize,
    pub value: CM::Scalar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalAggregatedProof<CM: CommitmentDef> {
    pub coordinates: [ReciprocalCoordinateClaim<CM>; 4],
    pub opening_witness: Option<ReciprocalWitness<CM>>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalWrapperError {
    #[error(transparent)]
    Type(#[from] ReciprocalTypeError),
    #[error("commitment mismatch between the aggregated proof and the public instance")]
    CommitmentMismatch,
    #[error("descriptor mismatch between the aggregated proof and the public instance")]
    DescriptorMismatch,
    #[error("coordinate mismatch: expected coordinate {expected}, got {actual}")]
    CoordinateMismatch { expected: usize, actual: usize },
    #[error("output mismatch at coordinate {coordinate}")]
    OutputMismatch { coordinate: usize },
    #[error("missing opening witness in reciprocal aggregated proof")]
    MissingOpeningWitness,
    #[error("commitment opening failed for the reciprocal proof witness")]
    OpeningMismatch,
    #[error("reciprocal trace mismatch in opening witness")]
    TraceMismatch,
}

#[derive(Clone, Debug, Default)]
pub struct ReciprocalWrapper;

impl ReciprocalWrapper {
    pub fn decompose<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
    ) -> [ReciprocalCoordinateClaim<CM>; 4] {
        core::array::from_fn(|i| ReciprocalCoordinateClaim {
            cm_x: instance.cm_x.clone(),
            descriptor: instance.descriptor.clone(),
            coordinate: i,
            value: instance.y[i],
        })
    }

    pub fn aggregate<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        coordinates: [ReciprocalCoordinateClaim<CM>; 4],
    ) -> Result<ReciprocalAggregatedProof<CM>, ReciprocalWrapperError> {
        Self::check_coordinate_claims(instance, &coordinates)?;
        Ok(ReciprocalAggregatedProof {
            coordinates,
            opening_witness: None,
        })
    }

    pub fn aggregate_in_lane<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        coordinates: [ReciprocalCoordinateClaim<CM>; 4],
    ) -> Result<ReciprocalAggregatedProof<CM>, ReciprocalWrapperError> {
        Self::ensure_lane_accepts(lane, instance)?;
        Self::aggregate(instance, coordinates)
    }

    pub fn verify<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<(), ReciprocalWrapperError> {
        Self::check_coordinate_claims(instance, &proof.coordinates)
    }

    pub fn verify_in_lane<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<(), ReciprocalWrapperError> {
        Self::ensure_lane_accepts(lane, instance)?;
        Self::verify(instance, proof)
    }

    pub fn prove_opening<CM: CommitmentOps>(
        ck: &CM::Key,
        instance: &ReciprocalPublicInstance<CM>,
        witness: ReciprocalWitness<CM>,
    ) -> Result<ReciprocalAggregatedProof<CM>, ReciprocalWrapperError>
    where
        CM::Scalar: PrimeField,
    {
        CM::open(ck, &witness.x, &witness.omega, &instance.cm_x)
            .map_err(|_| ReciprocalWrapperError::OpeningMismatch)?;
        let (expected_trace, expected_y) =
            reciprocal_n4_trace_and_output(&instance.descriptor, &witness.x)?;
        if witness.trace.len() != RECIPROCAL_N4_TRACE_LEN || witness.trace != expected_trace {
            return Err(ReciprocalWrapperError::TraceMismatch);
        }
        Self::check_output(instance, &expected_y)?;
        Ok(ReciprocalAggregatedProof {
            coordinates: Self::decompose(instance),
            opening_witness: Some(witness),
        })
    }

    pub fn verify_opening<CM: CommitmentOps>(
        ck: &CM::Key,
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<(), ReciprocalWrapperError>
    where
        CM::Scalar: PrimeField,
    {
        Self::check_coordinate_claims(instance, &proof.coordinates)?;
        let witness = proof
            .opening_witness
            .as_ref()
            .ok_or(ReciprocalWrapperError::MissingOpeningWitness)?;
        CM::open(ck, &witness.x, &witness.omega, &instance.cm_x)
            .map_err(|_| ReciprocalWrapperError::OpeningMismatch)?;
        let (expected_trace, expected_y) =
            reciprocal_n4_trace_and_output(&instance.descriptor, &witness.x)?;
        if witness.trace.len() != RECIPROCAL_N4_TRACE_LEN || witness.trace != expected_trace {
            return Err(ReciprocalWrapperError::TraceMismatch);
        }
        Self::check_output(instance, &expected_y)
    }

    pub fn prove_opening_in_lane<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        witness: ReciprocalWitness<CM>,
    ) -> Result<ReciprocalAggregatedProof<CM>, ReciprocalWrapperError>
    where
        CM::Scalar: PrimeField,
    {
        Self::ensure_lane_accepts(lane, instance)?;
        Self::prove_opening(ck, instance, witness)
    }

    pub fn verify_opening_in_lane<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<(), ReciprocalWrapperError>
    where
        CM::Scalar: PrimeField,
    {
        Self::ensure_lane_accepts(lane, instance)?;
        Self::verify_opening(ck, instance, proof)
    }

    fn ensure_lane_accepts<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
    ) -> Result<(), ReciprocalWrapperError> {
        match lane.check_instance(instance) {
            Ok(()) => Ok(()),
            Err(ReciprocalTypeError::DescriptorMismatch) => {
                Err(ReciprocalWrapperError::DescriptorMismatch)
            }
            Err(err) => Err(err.into()),
        }
    }

    fn check_coordinate_claims<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        coordinates: &[ReciprocalCoordinateClaim<CM>; 4],
    ) -> Result<(), ReciprocalWrapperError> {
        for (i, claim) in coordinates.iter().enumerate() {
            if claim.cm_x != instance.cm_x {
                return Err(ReciprocalWrapperError::CommitmentMismatch);
            }
            if claim.descriptor != instance.descriptor {
                return Err(ReciprocalWrapperError::DescriptorMismatch);
            }
            if claim.coordinate != i {
                return Err(ReciprocalWrapperError::CoordinateMismatch {
                    expected: i,
                    actual: claim.coordinate,
                });
            }
            if claim.value != instance.y[i] {
                return Err(ReciprocalWrapperError::OutputMismatch { coordinate: i });
            }
        }
        Ok(())
    }

    fn check_output<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        expected_y: &[CM::Scalar; 4],
    ) -> Result<(), ReciprocalWrapperError> {
        for (i, expected) in expected_y.iter().enumerate() {
            if instance.y[i] != *expected {
                return Err(ReciprocalWrapperError::OutputMismatch { coordinate: i });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use ark_ec::PrimeGroup;
    use ark_std::rand::thread_rng;
    use sonobe_primitives::commitments::{CommitmentOps, pedersen::Pedersen};

    use super::{
        ReciprocalAggregatedProof, ReciprocalCoordinateClaim, ReciprocalWrapper,
        ReciprocalWrapperError,
    };
    use crate::compilers::cyclefold::adapters::reciprocal_types::{
        ReciprocalPublicInstance, ReciprocalSameQLane, ReciprocalWitness,
        reciprocal_n4_trace_and_output,
    };

    type TestCM = Pedersen<G1Projective, true>;

    fn sample_wrapper_fixture() -> (
        <TestCM as sonobe_primitives::commitments::CommitmentDef>::Key,
        ReciprocalPublicInstance<TestCM>,
        ReciprocalWitness<TestCM>,
    ) {
        let mut rng = thread_rng();
        let q = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let x = vec![5_u64.into(), 6_u64.into(), 7_u64.into(), 8_u64.into()];
        let ck =
            TestCM::generate_key(x.len(), &mut rng).expect("commitment key generation should work");
        let (cm_x, omega) =
            TestCM::commit(&ck, &x, &mut rng).expect("commitment generation should work");
        let (trace, y) = reciprocal_n4_trace_and_output(&q, &x)
            .expect("worked reciprocal evaluator should work");
        let instance = ReciprocalPublicInstance {
            cm_x,
            descriptor: q,
            y,
        };
        let witness = ReciprocalWitness { x, trace, omega };
        (ck, instance, witness)
    }

    #[test]
    fn test_reciprocal_wrapper_accepts_consistent_proof() {
        let (_, instance, _) = sample_wrapper_fixture();
        let proof =
            ReciprocalWrapper::aggregate(&instance, ReciprocalWrapper::decompose(&instance))
                .expect("wrapper should accept self-consistent coordinates");

        assert_eq!(proof.coordinates.len(), 4);
        assert!(proof.opening_witness.is_none());
        assert_eq!(ReciprocalWrapper::verify(&instance, &proof), Ok(()));
    }

    #[test]
    fn test_reciprocal_wrapper_rejects_descriptor_mismatch() {
        let (_, instance, _) = sample_wrapper_fixture();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[2].descriptor = vec![9_u64.into(), 9_u64.into(), 9_u64.into(), 9_u64.into()];

        assert_eq!(
            ReciprocalWrapper::aggregate(&instance, coordinates),
            Err(ReciprocalWrapperError::DescriptorMismatch)
        );
    }

    #[test]
    fn test_reciprocal_wrapper_rejects_commitment_mismatch() {
        let (_, instance, _) = sample_wrapper_fixture();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[1].cm_x = G1Projective::generator();

        assert_eq!(
            ReciprocalWrapper::aggregate(&instance, coordinates),
            Err(ReciprocalWrapperError::CommitmentMismatch)
        );
    }

    #[test]
    fn test_reciprocal_wrapper_rejects_output_mismatch() {
        let (_, instance, _) = sample_wrapper_fixture();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[3].value = 99_u64.into();

        assert_eq!(
            ReciprocalWrapper::aggregate(&instance, coordinates),
            Err(ReciprocalWrapperError::OutputMismatch { coordinate: 3 })
        );
    }

    #[test]
    fn test_reciprocal_wrapper_verify_in_lane() {
        let (_, instance, _) = sample_wrapper_fixture();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.descriptor.clone())
            .expect("worked instance should define a valid same-q lane");
        let proof = ReciprocalAggregatedProof {
            coordinates: ReciprocalWrapper::decompose(&instance),
            opening_witness: None,
        };

        assert_eq!(
            ReciprocalWrapper::verify_in_lane(&lane, &instance, &proof),
            Ok(())
        );
    }

    #[test]
    fn test_wrapper_rejects_wrong_coordinate_index() {
        let (_, instance, _) = sample_wrapper_fixture();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[0] = ReciprocalCoordinateClaim {
            coordinate: 1,
            ..coordinates[0].clone()
        };

        assert_eq!(
            ReciprocalWrapper::aggregate(&instance, coordinates),
            Err(ReciprocalWrapperError::CoordinateMismatch {
                expected: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn test_reciprocal_wrapper_prove_and_verify_opening() {
        let (ck, instance, witness) = sample_wrapper_fixture();
        let proof = ReciprocalWrapper::prove_opening(&ck, &instance, witness)
            .expect("opening proof construction should work");

        assert!(proof.opening_witness.is_some());
        assert_eq!(
            ReciprocalWrapper::verify_opening(&ck, &instance, &proof),
            Ok(())
        );
    }

    #[test]
    fn test_verify_opening_rejects_tampered_trace() {
        let (ck, instance, witness) = sample_wrapper_fixture();
        let mut proof = ReciprocalWrapper::prove_opening(&ck, &instance, witness)
            .expect("opening proof construction should work");
        let opening = proof
            .opening_witness
            .as_mut()
            .expect("opening witness should be present");
        opening.trace[0] +=
            <TestCM as sonobe_primitives::commitments::CommitmentDef>::Scalar::from(1_u64);

        assert_eq!(
            ReciprocalWrapper::verify_opening(&ck, &instance, &proof),
            Err(ReciprocalWrapperError::TraceMismatch)
        );
    }

    #[test]
    fn test_verify_opening_rejects_missing_witness() {
        let (_, instance, _) = sample_wrapper_fixture();
        let proof =
            ReciprocalWrapper::aggregate(&instance, ReciprocalWrapper::decompose(&instance))
                .expect("projection-only aggregation should still work");
        let mut rng = thread_rng();
        let ck = TestCM::generate_key(4, &mut rng).expect("commitment key generation should work");

        assert_eq!(
            ReciprocalWrapper::verify_opening(&ck, &instance, &proof),
            Err(ReciprocalWrapperError::MissingOpeningWitness)
        );
    }
}
