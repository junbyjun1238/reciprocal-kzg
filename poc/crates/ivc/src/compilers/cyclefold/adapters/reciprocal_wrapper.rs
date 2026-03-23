//! Reciprocal wrapper helpers that treat 4 coordinate claims as a single
//! verifier-visible object.

use thiserror::Error;

use super::reciprocal_types::{
    RECIPROCAL_N4_TRACE_LEN, ReciprocalPublicInstance, ReciprocalSameQLane,
    ReciprocalTypeError, ReciprocalWitness, reciprocal_n4_trace_and_output,
};
use sonobe_primitives::commitments::{CommitmentDef, CommitmentOps};
use ark_ff::PrimeField;

/// [`ReciprocalCoordinateClaim`] is a scalarized coordinate-level claim derived
/// from a reciprocal public instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalCoordinateClaim<CM: CommitmentDef> {
    /// Commitment to the input vector `x`.
    pub cm_x: CM::Commitment,
    /// Public descriptor.
    pub q: Vec<CM::Scalar>,
    /// Coordinate index in `{0,1,2,3}`.
    pub coordinate: usize,
    /// Claimed coordinate value.
    pub value: CM::Scalar,
}

/// [`ReciprocalAggregatedProof`] is the PoC-level proof object exported by the
/// wrapper layer.
///
/// The verifier-visible projection is the 4-coordinate claim bundle. When the
/// PoC runs with a real opening path, the proof also carries an opening witness
/// `(x, trace, omega)` that can be checked offchain against `(C, q, y)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalAggregatedProof<CM: CommitmentDef> {
    /// The four coordinate claims that were wrapped into one object.
    pub coordinates: [ReciprocalCoordinateClaim<CM>; 4],
    /// Optional opening witness used by the current offchain PoC verifier.
    pub opening_witness: Option<ReciprocalWitness<CM>>,
}

/// [`ReciprocalWrapperError`] enumerates wrapper-level failures detected before
/// the actual cryptographic opening layer is plugged in.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalWrapperError {
    /// The wrapper received malformed reciprocal helper data.
    #[error(transparent)]
    Type(#[from] ReciprocalTypeError),
    /// The coordinate claim does not use the expected commitment.
    #[error("commitment mismatch between the aggregated proof and the public instance")]
    CommitmentMismatch,
    /// The coordinate claim does not use the expected descriptor.
    #[error("descriptor mismatch between the aggregated proof and the public instance")]
    DescriptorMismatch,
    /// The coordinate position is not the expected one.
    #[error("coordinate mismatch: expected coordinate {expected}, got {actual}")]
    CoordinateMismatch {
        /// The expected coordinate position.
        expected: usize,
        /// The received coordinate position.
        actual: usize,
    },
    /// The coordinate value is not the expected one from the public output.
    #[error("output mismatch at coordinate {coordinate}")]
    OutputMismatch {
        /// The coordinate where the mismatch occurred.
        coordinate: usize,
    },
    /// The proof does not contain the opening witness required by the current
    /// offchain opening verifier.
    #[error("missing opening witness in reciprocal aggregated proof")]
    MissingOpeningWitness,
    /// The opening witness does not verify against the commitment.
    #[error("commitment opening failed for the reciprocal proof witness")]
    OpeningMismatch,
    /// The reciprocal trace inside the proof witness is malformed.
    #[error("reciprocal trace mismatch in opening witness")]
    TraceMismatch,
}

/// [`ReciprocalWrapper`] provides helpers for splitting and re-aggregating a
/// reciprocal public instance.
#[derive(Clone, Debug, Default)]
pub struct ReciprocalWrapper;

impl ReciprocalWrapper {
    /// Decomposes the public instance into four coordinate-level claims.
    pub fn decompose<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
    ) -> [ReciprocalCoordinateClaim<CM>; 4] {
        core::array::from_fn(|i| ReciprocalCoordinateClaim {
            cm_x: instance.cm_x.clone(),
            q: instance.q.clone(),
            coordinate: i,
            value: instance.y[i],
        })
    }

    /// Aggregates four coordinate claims into one verifier-visible object after
    /// checking that they match the target public instance exactly.
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

    /// Verifies the wrapper-level consistency of a single aggregated proof
    /// object against the public instance.
    pub fn verify<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<(), ReciprocalWrapperError> {
        Self::check_coordinate_claims(instance, &proof.coordinates)
    }

    /// Verifies wrapper-level consistency under a fixed same-`q` lane.
    pub fn verify_in_lane<CM: CommitmentDef>(
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<(), ReciprocalWrapperError> {
        if !lane.accepts(instance) {
            return Err(ReciprocalWrapperError::DescriptorMismatch);
        }
        Self::verify(instance, proof)
    }

    /// Builds a proof object that carries a real opening witness for the
    /// worked reciprocal `N=4` evaluator.
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
            reciprocal_n4_trace_and_output(&instance.q, &witness.x)?;
        if witness.trace.len() != RECIPROCAL_N4_TRACE_LEN || witness.trace != expected_trace {
            return Err(ReciprocalWrapperError::TraceMismatch);
        }
        Self::check_output(instance, &expected_y)?;
        Ok(ReciprocalAggregatedProof {
            coordinates: Self::decompose(instance),
            opening_witness: Some(witness),
        })
    }

    /// Verifies the opening witness carried by a reciprocal aggregated proof.
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
            reciprocal_n4_trace_and_output(&instance.q, &witness.x)?;
        if witness.trace.len() != RECIPROCAL_N4_TRACE_LEN || witness.trace != expected_trace {
            return Err(ReciprocalWrapperError::TraceMismatch);
        }
        Self::check_output(instance, &expected_y)
    }

    /// Same as [`ReciprocalWrapper::prove_opening`], but requires the statement
    /// to stay inside a fixed same-`q` lane.
    pub fn prove_opening_in_lane<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        witness: ReciprocalWitness<CM>,
    ) -> Result<ReciprocalAggregatedProof<CM>, ReciprocalWrapperError>
    where
        CM::Scalar: PrimeField,
    {
        if !lane.accepts(instance) {
            return Err(ReciprocalWrapperError::DescriptorMismatch);
        }
        Self::prove_opening(ck, instance, witness)
    }

    /// Same as [`ReciprocalWrapper::verify_opening`], but also checks the
    /// same-`q` lane policy.
    pub fn verify_opening_in_lane<CM: CommitmentOps>(
        ck: &CM::Key,
        lane: &ReciprocalSameQLane<CM>,
        instance: &ReciprocalPublicInstance<CM>,
        proof: &ReciprocalAggregatedProof<CM>,
    ) -> Result<(), ReciprocalWrapperError>
    where
        CM::Scalar: PrimeField,
    {
        if !lane.accepts(instance) {
            return Err(ReciprocalWrapperError::DescriptorMismatch);
        }
        Self::verify_opening(ck, instance, proof)
    }

    fn check_coordinate_claims<CM: CommitmentDef>(
        instance: &ReciprocalPublicInstance<CM>,
        coordinates: &[ReciprocalCoordinateClaim<CM>; 4],
    ) -> Result<(), ReciprocalWrapperError> {
        for (i, claim) in coordinates.iter().enumerate() {
            if claim.cm_x != instance.cm_x {
                return Err(ReciprocalWrapperError::CommitmentMismatch);
            }
            if claim.q != instance.q {
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
    use ark_ec::PrimeGroup;
    use ark_bn254::G1Projective;
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

    fn sample_bundle() -> (
        <TestCM as sonobe_primitives::commitments::CommitmentDef>::Key,
        ReciprocalPublicInstance<TestCM>,
        ReciprocalWitness<TestCM>,
    ) {
        let mut rng = thread_rng();
        let q = vec![1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()];
        let x = vec![5_u64.into(), 6_u64.into(), 7_u64.into(), 8_u64.into()];
        let ck = TestCM::generate_key(x.len(), &mut rng).expect("commitment key generation should work");
        let (cm_x, omega) =
            TestCM::commit(&ck, &x, &mut rng).expect("commitment generation should work");
        let (trace, y) =
            reciprocal_n4_trace_and_output(&q, &x).expect("worked reciprocal evaluator should work");
        let instance = ReciprocalPublicInstance { cm_x, q, y };
        let witness = ReciprocalWitness { x, trace, omega };
        (ck, instance, witness)
    }

    #[test]
    fn test_reciprocal_wrapper_accepts_consistent_proof() {
        let (_, instance, _) = sample_bundle();
        let proof = ReciprocalWrapper::aggregate(&instance, ReciprocalWrapper::decompose(&instance))
            .expect("wrapper should accept self-consistent coordinates");

        assert_eq!(proof.coordinates.len(), 4);
        assert!(proof.opening_witness.is_none());
        assert_eq!(ReciprocalWrapper::verify(&instance, &proof), Ok(()));
    }

    #[test]
    fn test_reciprocal_wrapper_rejects_descriptor_mismatch() {
        let (_, instance, _) = sample_bundle();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[2].q = vec![9_u64.into(), 9_u64.into(), 9_u64.into(), 9_u64.into()];

        assert_eq!(
            ReciprocalWrapper::aggregate(&instance, coordinates),
            Err(ReciprocalWrapperError::DescriptorMismatch)
        );
    }

    #[test]
    fn test_reciprocal_wrapper_rejects_commitment_mismatch() {
        let (_, instance, _) = sample_bundle();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[1].cm_x = G1Projective::generator();

        assert_eq!(
            ReciprocalWrapper::aggregate(&instance, coordinates),
            Err(ReciprocalWrapperError::CommitmentMismatch)
        );
    }

    #[test]
    fn test_reciprocal_wrapper_rejects_output_mismatch() {
        let (_, instance, _) = sample_bundle();
        let mut coordinates = ReciprocalWrapper::decompose(&instance);
        coordinates[3].value = 99_u64.into();

        assert_eq!(
            ReciprocalWrapper::aggregate(&instance, coordinates),
            Err(ReciprocalWrapperError::OutputMismatch { coordinate: 3 })
        );
    }

    #[test]
    fn test_reciprocal_wrapper_verify_in_lane() {
        let (_, instance, _) = sample_bundle();
        let lane = ReciprocalSameQLane::<TestCM>::new(instance.q.clone());
        let proof = ReciprocalAggregatedProof {
            coordinates: ReciprocalWrapper::decompose(&instance),
            opening_witness: None,
        };

        assert_eq!(ReciprocalWrapper::verify_in_lane(&lane, &instance, &proof), Ok(()));
    }

    #[test]
    fn test_reciprocal_wrapper_rejects_coordinate_position_mismatch() {
        let (_, instance, _) = sample_bundle();
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
        let (ck, instance, witness) = sample_bundle();
        let proof = ReciprocalWrapper::prove_opening(&ck, &instance, witness)
            .expect("opening proof construction should work");

        assert!(proof.opening_witness.is_some());
        assert_eq!(ReciprocalWrapper::verify_opening(&ck, &instance, &proof), Ok(()));
    }

    #[test]
    fn test_reciprocal_wrapper_verify_opening_rejects_tampered_trace() {
        let (ck, instance, witness) = sample_bundle();
        let mut proof = ReciprocalWrapper::prove_opening(&ck, &instance, witness)
            .expect("opening proof construction should work");
        let opening = proof
            .opening_witness
            .as_mut()
            .expect("opening witness should be present");
        opening.trace[0] += <TestCM as sonobe_primitives::commitments::CommitmentDef>::Scalar::from(1_u64);

        assert_eq!(
            ReciprocalWrapper::verify_opening(&ck, &instance, &proof),
            Err(ReciprocalWrapperError::TraceMismatch)
        );
    }

    #[test]
    fn test_reciprocal_wrapper_verify_opening_rejects_missing_witness() {
        let (_, instance, _) = sample_bundle();
        let proof = ReciprocalWrapper::aggregate(&instance, ReciprocalWrapper::decompose(&instance))
            .expect("projection-only aggregation should still work");
        let mut rng = thread_rng();
        let ck = TestCM::generate_key(4, &mut rng).expect("commitment key generation should work");

        assert_eq!(
            ReciprocalWrapper::verify_opening(&ck, &instance, &proof),
            Err(ReciprocalWrapperError::MissingOpeningWitness)
        );
    }
}
