use ark_std::{borrow::Borrow, rand::RngCore};
use sonobe_primitives::{relations::Relation, transcripts::Transcript};

use super::{FoldingSchemeDef, errors::Error, keys::DeciderKey};

pub struct FoldStep<FS: FoldingSchemeDef, const M: usize, const N: usize> {
    pub next_running_witness: FS::RW,
    pub next_running_instance: FS::RU,
    pub proof: FS::Proof<M, N>,
    pub challenge: FS::Challenge,
}

impl<FS: FoldingSchemeDef, const M: usize, const N: usize> FoldStep<FS, M, N> {
    pub fn into_parts(self) -> (FS::RW, FS::RU, FS::Proof<M, N>, FS::Challenge) {
        (
            self.next_running_witness,
            self.next_running_instance,
            self.proof,
            self.challenge,
        )
    }
}

pub trait FoldingSchemePreprocessor: FoldingSchemeDef {
    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;
}

pub trait FoldingSchemeKeyGenerator: FoldingSchemeDef {
    fn generate_keys(pp: Self::PublicParam, arith: Self::Arith) -> Result<Self::DeciderKey, Error>;
}

pub trait FoldingSchemeProver<const M: usize, const N: usize>: FoldingSchemeDef {
    fn fold(
        proving_key: &<Self::DeciderKey as DeciderKey>::ProverKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        running_witnesses: &[impl Borrow<Self::RW>; M],
        running_instances: &[impl Borrow<Self::RU>; M],
        incoming_witnesses: &[impl Borrow<Self::IW>; N],
        incoming_instances: &[impl Borrow<Self::IU>; N],
        rng: impl RngCore,
    ) -> Result<FoldStep<Self, M, N>, Error>
    where
        Self: Sized;

    #[allow(clippy::type_complexity)]
    fn prove(
        proving_key: &<Self::DeciderKey as DeciderKey>::ProverKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        running_witnesses: &[impl Borrow<Self::RW>; M],
        running_instances: &[impl Borrow<Self::RU>; M],
        incoming_witnesses: &[impl Borrow<Self::IW>; N],
        incoming_instances: &[impl Borrow<Self::IU>; N],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<M, N>, Self::Challenge), Error>
    where
        Self: Sized,
    {
        Self::fold(
            proving_key,
            transcript,
            running_witnesses,
            running_instances,
            incoming_witnesses,
            incoming_instances,
            rng,
        )
        .map(|step| step.into_parts())
    }
}

pub trait FoldingSchemeVerifier<const M: usize, const N: usize>: FoldingSchemeDef {
    fn verify(
        verifying_key: &<Self::DeciderKey as DeciderKey>::VerifierKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        running_instances: &[impl Borrow<Self::RU>; M],
        incoming_instances: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, Error>;
}

pub trait FoldingSchemeDecider: FoldingSchemeDef {
    fn decide_running(
        decider_key: &Self::DeciderKey,
        running_witness: &Self::RW,
        running_instance: &Self::RU,
    ) -> Result<(), Error> {
        Relation::<Self::RW, Self::RU>::check_relation(
            decider_key,
            running_witness,
            running_instance,
        )
    }

    fn decide_incoming(
        decider_key: &Self::DeciderKey,
        incoming_witness: &Self::IW,
        incoming_instance: &Self::IU,
    ) -> Result<(), Error> {
        Relation::<Self::IW, Self::IU>::check_relation(
            decider_key,
            incoming_witness,
            incoming_instance,
        )
    }
}

impl<FS: FoldingSchemeDef> FoldingSchemeDecider for FS {}

pub trait FoldingScheme<const M: usize, const N: usize>:
    FoldingSchemePreprocessor
    + FoldingSchemeKeyGenerator
    + FoldingSchemeProver<M, N>
    + FoldingSchemeVerifier<M, N>
    + FoldingSchemeDecider
{
}

impl<FS, const M: usize, const N: usize> FoldingScheme<M, N> for FS where
    FS: FoldingSchemePreprocessor
        + FoldingSchemeKeyGenerator
        + FoldingSchemeProver<M, N>
        + FoldingSchemeVerifier<M, N>
        + FoldingSchemeDecider
{
}

pub trait FoldingSchemeOps<const M: usize, const N: usize>: FoldingScheme<M, N> {}

impl<FS, const M: usize, const N: usize> FoldingSchemeOps<M, N> for FS where FS: FoldingScheme<M, N> {}
