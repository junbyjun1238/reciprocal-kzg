use ark_ff::PrimeField;
use sonobe_primitives::{commitments::CommitmentDef, transcripts::Absorbable};
use thiserror::Error;

pub type ReciprocalOutput<S> = [S; 4];

pub const RECIPROCAL_N4_INPUT_LEN: usize = 4;
pub const RECIPROCAL_N4_TRACE_LEN: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalPublicInstance<CM: CommitmentDef> {
    pub cm_x: CM::Commitment,
    pub descriptor: Vec<CM::Scalar>,
    pub y: ReciprocalOutput<CM::Scalar>,
}

impl<CM: CommitmentDef> ReciprocalPublicInstance<CM> {
    pub fn same_descriptor_as(&self, other: &Self) -> bool {
        self.descriptor == other.descriptor
    }
}

impl<CM: CommitmentDef> Absorbable for ReciprocalPublicInstance<CM> {
    fn absorb_into<F: ark_ff::PrimeField>(&self, dest: &mut Vec<F>) {
        self.descriptor.absorb_into(dest);
        self.y.absorb_into(dest);
        self.cm_x.absorb_into(dest);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalWitness<CM: CommitmentDef> {
    pub x: Vec<CM::Scalar>,
    pub trace: Vec<CM::Scalar>,
    pub omega: CM::Randomness,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReciprocalTypeError {
    #[error("descriptor mismatch: expected the same q for both instances")]
    DescriptorMismatch,
    #[error("invalid descriptor length: expected {expected}, got {actual}")]
    DescriptorLengthMismatch { expected: usize, actual: usize },
    #[error("invalid input length: expected {expected}, got {actual}")]
    InputLengthMismatch { expected: usize, actual: usize },
}

pub fn validate_worked_n4_descriptor<S>(descriptor: &[S]) -> Result<(), ReciprocalTypeError> {
    if descriptor.len() != RECIPROCAL_N4_INPUT_LEN {
        return Err(ReciprocalTypeError::DescriptorLengthMismatch {
            expected: RECIPROCAL_N4_INPUT_LEN,
            actual: descriptor.len(),
        });
    }
    Ok(())
}

pub fn validate_worked_n4_instance<CM: CommitmentDef>(
    instance: &ReciprocalPublicInstance<CM>,
) -> Result<(), ReciprocalTypeError> {
    validate_worked_n4_descriptor(&instance.descriptor)
}

pub fn reciprocal_n4_trace_and_output<S: PrimeField>(
    q: &[S],
    x: &[S],
) -> Result<(Vec<S>, ReciprocalOutput<S>), ReciprocalTypeError> {
    validate_worked_n4_descriptor(q)?;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReciprocalSameQLane<CM: CommitmentDef> {
    descriptor: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> ReciprocalSameQLane<CM> {
    pub fn new(descriptor: Vec<CM::Scalar>) -> Result<Self, ReciprocalTypeError> {
        validate_worked_n4_descriptor(&descriptor)?;
        Ok(Self { descriptor })
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked(descriptor: Vec<CM::Scalar>) -> Self {
        Self { descriptor }
    }

    pub fn descriptor(&self) -> &[CM::Scalar] {
        &self.descriptor
    }

    pub fn bind_instance(
        &self,
        cm_x: CM::Commitment,
        y: ReciprocalOutput<CM::Scalar>,
    ) -> ReciprocalPublicInstance<CM> {
        ReciprocalPublicInstance {
            cm_x,
            descriptor: self.descriptor.clone(),
            y,
        }
    }

    pub fn accepts(&self, instance: &ReciprocalPublicInstance<CM>) -> bool {
        instance.descriptor == self.descriptor
    }

    pub fn check_instance(
        &self,
        instance: &ReciprocalPublicInstance<CM>,
    ) -> Result<(), ReciprocalTypeError> {
        validate_worked_n4_instance(instance)?;
        if self.accepts(instance) {
            Ok(())
        } else {
            Err(ReciprocalTypeError::DescriptorMismatch)
        }
    }

    pub fn check_instance_pair(
        &self,
        left: &ReciprocalPublicInstance<CM>,
        right: &ReciprocalPublicInstance<CM>,
    ) -> Result<(), ReciprocalTypeError> {
        self.check_instance(left)?;
        self.check_instance(right)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use sonobe_primitives::commitments::pedersen::Pedersen;

    use super::{
        RECIPROCAL_N4_INPUT_LEN, RECIPROCAL_N4_TRACE_LEN, ReciprocalOutput,
        ReciprocalPublicInstance, ReciprocalSameQLane, ReciprocalTypeError, ReciprocalWitness,
        reciprocal_n4_trace_and_output,
    };

    type TestCM = Pedersen<G1Projective, true>;

    fn sample_output(
        a: u64,
        b: u64,
        c: u64,
        d: u64,
    ) -> ReciprocalOutput<<TestCM as sonobe_primitives::commitments::CommitmentDef>::Scalar> {
        [a.into(), b.into(), c.into(), d.into()]
    }

    #[test]
    fn test_same_q_lane_accepts_bound_instances() {
        let lane = ReciprocalSameQLane::<TestCM>::new(vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
        ])
        .expect("worked N=4 descriptor should define a valid lane");
        let instance = lane.bind_instance(Default::default(), sample_output(10, 11, 12, 13));

        assert!(lane.accepts(&instance));
        assert_eq!(lane.descriptor(), instance.descriptor.as_slice());
    }

    #[test]
    fn test_same_q_lane_rejects_descriptor_mismatch() {
        let lane = ReciprocalSameQLane::<TestCM>::new(vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
        ])
        .expect("worked N=4 descriptor should define a valid lane");
        let left = lane.bind_instance(Default::default(), sample_output(1, 2, 3, 4));
        let right = ReciprocalPublicInstance::<TestCM> {
            cm_x: Default::default(),
            descriptor: vec![9_u64.into(), 9_u64.into(), 9_u64.into(), 9_u64.into()],
            y: sample_output(5, 6, 7, 8),
        };

        assert_eq!(
            lane.check_instance_pair(&left, &right),
            Err(ReciprocalTypeError::DescriptorMismatch)
        );
        assert!(!left.same_descriptor_as(&right));
    }

    #[test]
    fn test_same_q_lane_rejects_non_n4_instance_descriptor() {
        let lane = ReciprocalSameQLane::<TestCM>::new(vec![
            1_u64.into(),
            2_u64.into(),
            3_u64.into(),
            4_u64.into(),
        ])
        .expect("worked N=4 descriptor should define a valid lane");
        let instance = ReciprocalPublicInstance::<TestCM> {
            cm_x: Default::default(),
            descriptor: vec![1_u64.into(), 2_u64.into(), 3_u64.into()],
            y: sample_output(5, 6, 7, 8),
        };

        assert_eq!(
            lane.check_instance(&instance),
            Err(ReciprocalTypeError::DescriptorLengthMismatch {
                expected: RECIPROCAL_N4_INPUT_LEN,
                actual: 3,
            })
        );
    }

    #[test]
    fn test_same_q_lane_new_rejects_non_n4_descriptor() {
        assert_eq!(
            ReciprocalSameQLane::<TestCM>::new(vec![1_u64.into(), 2_u64.into(), 3_u64.into()]),
            Err(ReciprocalTypeError::DescriptorLengthMismatch {
                expected: RECIPROCAL_N4_INPUT_LEN,
                actual: 3,
            })
        );
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
