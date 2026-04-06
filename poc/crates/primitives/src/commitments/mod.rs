use ark_ff::UniformRand;
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, fields::fp::FpVar, select::CondSelectGadget};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    fmt::Debug,
    iter::Sum,
    ops::{Add, Mul},
    rand::RngCore,
};
use thiserror::Error;

use crate::{
    algebra::{
        Val,
        field::{TwoStageFieldVar, emulated::EmulatedFieldVar},
        group::emulated::EmulatedAffineVar,
        ops::bits::FromBitsGadget,
    },
    traits::{CF1, CF2, SonobeCurve, SonobeField},
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod pedersen;

#[derive(Debug, Error)]
pub enum Error {
    #[error(
        "The message being committed to has length {1}, exceeding the maximum supported length ({0})"
    )]
    MessageTooLong(usize, usize),
    #[error("Commitment verification failed")]
    CommitmentVerificationFail,
}

pub trait CommitmentKey: Clone + Send + Sync + CanonicalSerialize + CanonicalDeserialize {
    fn max_scalars_len(&self) -> usize;
}

pub trait CommitmentDef: 'static + Clone + Debug + PartialEq + Eq {
    const IS_HIDING: bool;

    type Key: CommitmentKey;
    type Scalar: Clone + Copy + Default + Debug + PartialEq + Eq + Sync + Absorbable + UniformRand;
    type Commitment: Clone + Default + Debug + PartialEq + Eq + Sync + Absorbable;
    type Randomness: Clone
        + Copy
        + Default
        + Debug
        + PartialEq
        + Eq
        + Sync
        + Add<Self::Scalar, Output = Self::Randomness>
        + Mul<Self::Scalar, Output = Self::Randomness>
        + for<'a> Add<&'a Self::Scalar, Output = Self::Randomness>
        + for<'a> Mul<&'a Self::Scalar, Output = Self::Randomness>
        + Add<Output = Self::Randomness>
        + Mul<Output = Self::Randomness>
        + Sum;
}

pub trait CommitmentOps: CommitmentDef {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<Self::Key, Error>;

    fn commit(
        ck: &Self::Key,
        v: &[Self::Scalar],
        rng: impl RngCore,
    ) -> Result<(Self::Commitment, Self::Randomness), Error>;

    fn open(
        ck: &Self::Key,
        v: &[Self::Scalar],
        r: &Self::Randomness,
        cm: &Self::Commitment,
    ) -> Result<(), Error>;
}

pub trait CommitmentDefGadget: Clone {
    type ConstraintField: SonobeField;

    type KeyVar;
    type ScalarVar: AbsorbableVar<Self::ConstraintField>
        + CondSelectGadget<Self::ConstraintField>
        + FromBitsGadget<Self::ConstraintField>
        + AllocVar<<Self::Widget as CommitmentDef>::Scalar, Self::ConstraintField>
        + GR1CSVar<Self::ConstraintField, Value = <Self::Widget as CommitmentDef>::Scalar>
        + TwoStageFieldVar;
    type CommitmentVar: Clone
        + AbsorbableVar<Self::ConstraintField>
        + CondSelectGadget<Self::ConstraintField>
        + AllocVar<<Self::Widget as CommitmentDef>::Commitment, Self::ConstraintField>
        + GR1CSVar<Self::ConstraintField, Value = <Self::Widget as CommitmentDef>::Commitment>;
    type RandomnessVar: AllocVar<<Self::Widget as CommitmentDef>::Randomness, Self::ConstraintField>
        + GR1CSVar<Self::ConstraintField, Value = <Self::Widget as CommitmentDef>::Randomness>;

    type Widget: CommitmentDef;
}

pub trait CommitmentOpsGadget: CommitmentDefGadget {
    fn open(
        ck: &Self::KeyVar,
        v: &[Self::ScalarVar],
        r: &Self::RandomnessVar,
        cm: &Self::CommitmentVar,
    ) -> Result<(), SynthesisError>;
}

pub trait GroupBasedCommitment:
    CommitmentDef<Commitment: SonobeCurve, Scalar = CF1<<Self as CommitmentDef>::Commitment>>
    + CommitmentOps
{
    type Gadget1: CommitmentOpsGadget
        + CommitmentDefGadget<
            ConstraintField = CF2<Self::Commitment>,
            ScalarVar = EmulatedFieldVar<CF2<Self::Commitment>, Self::Scalar>,
            CommitmentVar = <Self::Commitment as Val>::Var,
            Widget = Self,
        >;
    type Gadget2: CommitmentDefGadget<
            ConstraintField = Self::Scalar,
            ScalarVar = FpVar<Self::Scalar>,
            CommitmentVar = EmulatedAffineVar<Self::Scalar, Self::Commitment>,
            Widget = Self,
        >;
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use ark_std::error::Error;

    use super::*;

    pub fn test_commitment_correctness<CM: CommitmentOps>(
        mut rng: impl RngCore,
        len: usize,
    ) -> Result<(), Box<dyn Error>> {
        let v = (0..len)
            .map(|_| CM::Scalar::rand(&mut rng))
            .collect::<Vec<_>>();

        let ck = CM::generate_key(len, &mut rng)?;
        let (cm, r) = CM::commit(&ck, &v, &mut rng)?;
        CM::open(&ck, &v, &r, &cm)?;
        Ok(())
    }
}
