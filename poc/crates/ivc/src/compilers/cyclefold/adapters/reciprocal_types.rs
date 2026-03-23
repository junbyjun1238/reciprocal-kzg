//! Reciprocal-specific out-of-circuit helper types for PoC integration.

use ark_ff::PrimeField;
use sonobe_primitives::{
    commitments::CommitmentDef,
    transcripts::Absorbable,
};
use thiserror::Error;

/// Fixed-width evaluator output used by the reciprocal PoC.
pub type ReciprocalOutput<S> = [S; 4];

/// Input length of the worked reciprocal evaluator used by the PoC.
pub const RECIPROCAL_N4_INPUT_LEN: usize = 4;
/// Trace length of the worked reciprocal evaluator used by the PoC.
pub const RECIPROCAL_N4_TRACE_LEN: usize = 12;

/// [`ReciprocalPublicInstance`] is the PoC-level public object corresponding to
/// the semantic tuple `(C, q, y)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalPublicInstance<CM: CommitmentDef> {
    /// Commitment to the input vector `x`.
    pub cm_x: CM::Commitment,
    /// Public descriptor for the reciprocal evaluator.
    pub q: Vec<CM::Scalar>,
    /// Claimed evaluator output in `F^4`.
    pub y: ReciprocalOutput<CM::Scalar>,
}

impl<CM: CommitmentDef> ReciprocalPublicInstance<CM> {
    /// Returns `true` if `self` and `other` belong to the same descriptor lane.
    pub fn same_q_as(&self, other: &Self) -> bool {
        self.q == other.q
    }
}

impl<CM: CommitmentDef> Absorbable for ReciprocalPublicInstance<CM> {
    fn absorb_into<F: ark_ff::PrimeField>(&self, dest: &mut Vec<F>) {
        self.q.absorb_into(dest);
        self.y.absorb_into(dest);
        self.cm_x.absorb_into(dest);
    }
}

/// [`ReciprocalWitness`] is the PoC-level out-of-circuit helper corresponding
/// to `(x, trace, \omega)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalWitness<CM: CommitmentDef> {
    /// Committed input vector.
    pub x: Vec<CM::Scalar>,
    /// Auxiliary reciprocal trace.
    pub trace: Vec<CM::Scalar>,
    /// Opening witness or commitment randomness.
    pub omega: CM::Randomness,
}

/// [`ReciprocalTypeError`] enumerates shape-level failures in the reciprocal
/// PoC helper layer.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalTypeError {
    /// The two instances do not belong to the same descriptor lane.
    #[error("descriptor mismatch: expected the same q for both instances")]
    DescriptorMismatch,
    /// The descriptor length does not match the worked `N=4` evaluator.
    #[error("invalid descriptor length: expected {expected}, got {actual}")]
    DescriptorLengthMismatch {
        /// The expected descriptor length.
        expected: usize,
        /// The provided descriptor length.
        actual: usize,
    },
    /// The input vector length does not match the worked `N=4` evaluator.
    #[error("invalid input length: expected {expected}, got {actual}")]
    InputLengthMismatch {
        /// The expected input length.
        expected: usize,
        /// The provided input length.
        actual: usize,
    },
}

/// Computes the worked reciprocal `N=4` trace and output from a descriptor
/// `q = mu_2` and a committed leaf vector `x`.
pub fn reciprocal_n4_trace_and_output<S: PrimeField>(
    q: &[S],
    x: &[S],
) -> Result<(Vec<S>, ReciprocalOutput<S>), ReciprocalTypeError> {
    if q.len() != RECIPROCAL_N4_INPUT_LEN {
        return Err(ReciprocalTypeError::DescriptorLengthMismatch {
            expected: RECIPROCAL_N4_INPUT_LEN,
            actual: q.len(),
        });
    }
    if x.len() != RECIPROCAL_N4_INPUT_LEN {
        return Err(ReciprocalTypeError::InputLengthMismatch {
            expected: RECIPROCAL_N4_INPUT_LEN,
            actual: x.len(),
        });
    }

    let x0 = x[0];
    let x1 = x[1];
    let x2 = x[2];
    let x3 = x[3];

    let s01 = [S::zero(), S::zero(), x1 - x0, x0];
    let s23 = [S::zero(), S::zero(), x3 - x2, x2];
    let delta2 = s23[2] - s01[2];
    let delta3 = s23[3] - s01[3];
    let u = [
        q[0] * delta3,
        q[1] * delta3,
        s01[2] + q[2] * delta3,
        s01[3] + delta2 + q[3] * delta3,
    ];
    let y = [
        u[3],
        u[2] + S::from(3_u64) * u[3],
        u[1] + S::from(2_u64) * u[2] + S::from(3_u64) * u[3],
        u[0] + u[1] + u[2] + u[3],
    ];

    let mut trace = Vec::with_capacity(RECIPROCAL_N4_TRACE_LEN);
    trace.extend_from_slice(&s01);
    trace.extend_from_slice(&s23);
    trace.extend_from_slice(&u);
    Ok((trace, y))
}

/// [`ReciprocalSameQLane`] stores a fixed descriptor lane for the PoC and acts
/// as a small builder that enforces the same-`q` policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalSameQLane<CM: CommitmentDef> {
    q: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> ReciprocalSameQLane<CM> {
    /// Creates a new same-`q` lane for the given descriptor.
    pub fn new(q: Vec<CM::Scalar>) -> Self {
        Self { q }
    }

    /// Returns the lane descriptor.
    pub fn q(&self) -> &[CM::Scalar] {
        &self.q
    }

    /// Creates a public instance inside this lane.
    pub fn bind(
        &self,
        cm_x: CM::Commitment,
        y: ReciprocalOutput<CM::Scalar>,
    ) -> ReciprocalPublicInstance<CM> {
        ReciprocalPublicInstance {
            cm_x,
            q: self.q.clone(),
            y,
        }
    }

    /// Returns `true` if the given instance belongs to this lane.
    pub fn accepts(&self, instance: &ReciprocalPublicInstance<CM>) -> bool {
        instance.q == self.q
    }

    /// Checks that the two instances belong to the same lane.
    pub fn check_pair(
        &self,
        left: &ReciprocalPublicInstance<CM>,
        right: &ReciprocalPublicInstance<CM>,
    ) -> Result<(), ReciprocalTypeError> {
        if self.accepts(left) && self.accepts(right) {
            Ok(())
        } else {
            Err(ReciprocalTypeError::DescriptorMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use sonobe_primitives::commitments::pedersen::Pedersen;

    use super::{
        RECIPROCAL_N4_TRACE_LEN, ReciprocalOutput, ReciprocalPublicInstance,
        ReciprocalSameQLane, ReciprocalTypeError, ReciprocalWitness,
        reciprocal_n4_trace_and_output,
    };

    type TestCM = Pedersen<G1Projective, true>;

    fn sample_output(a: u64, b: u64, c: u64, d: u64) -> ReciprocalOutput<<TestCM as sonobe_primitives::commitments::CommitmentDef>::Scalar> {
        [a.into(), b.into(), c.into(), d.into()]
    }

    #[test]
    fn test_same_q_lane_accepts_bound_instances() {
        let lane = ReciprocalSameQLane::<TestCM>::new(vec![1_u64.into(), 2_u64.into(), 3_u64.into()]);
        let instance = lane.bind(Default::default(), sample_output(10, 11, 12, 13));

        assert!(lane.accepts(&instance));
        assert_eq!(lane.q(), instance.q.as_slice());
    }

    #[test]
    fn test_same_q_lane_rejects_descriptor_mismatch() {
        let lane = ReciprocalSameQLane::<TestCM>::new(vec![1_u64.into(), 2_u64.into()]);
        let left = lane.bind(Default::default(), sample_output(1, 2, 3, 4));
        let right = ReciprocalPublicInstance::<TestCM> {
            cm_x: Default::default(),
            q: vec![9_u64.into(), 9_u64.into()],
            y: sample_output(5, 6, 7, 8),
        };

        assert_eq!(
            lane.check_pair(&left, &right),
            Err(ReciprocalTypeError::DescriptorMismatch)
        );
        assert!(!left.same_q_as(&right));
    }

    #[test]
    fn test_reciprocal_witness_shape() {
        let witness = ReciprocalWitness::<TestCM> {
            x: vec![1_u64.into(), 2_u64.into()],
            trace: vec![3_u64.into(), 4_u64.into(), 5_u64.into()],
            omega: Default::default(),
        };

        assert_eq!(witness.x.len(), 2);
        assert_eq!(witness.trace.len(), 3);
    }

    #[test]
    fn test_reciprocal_n4_trace_and_output_shape() {
        let (trace, y) = reciprocal_n4_trace_and_output::<
            <TestCM as sonobe_primitives::commitments::CommitmentDef>::Scalar,
        >(
            &[1_u64.into(), 2_u64.into(), 3_u64.into(), 4_u64.into()],
            &[5_u64.into(), 6_u64.into(), 7_u64.into(), 8_u64.into()],
        )
        .expect("worked reciprocal evaluator should accept length-4 inputs");

        assert_eq!(trace.len(), RECIPROCAL_N4_TRACE_LEN);
        assert_eq!(y.len(), 4);
    }
}
