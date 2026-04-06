use ark_std::{borrow::Borrow, rand::RngCore};
use sonobe_primitives::{relations::Relation, transcripts::Transcript};

use super::{FoldingSchemeDef, errors::Error, keys::DeciderKey};

pub trait FoldingSchemePreprocessor: FoldingSchemeDef {
    fn preprocess(config: Self::Config, rng: impl RngCore) -> Result<Self::PublicParam, Error>;
}

pub trait FoldingSchemeKeyGenerator: FoldingSchemeDef {
    fn generate_keys(pp: Self::PublicParam, arith: Self::Arith) -> Result<Self::DeciderKey, Error>;
}

pub trait FoldingSchemeProver<const M: usize, const N: usize>: FoldingSchemeDef {
    #[allow(non_snake_case, clippy::type_complexity)]
    fn prove(
        pk: &<Self::DeciderKey as DeciderKey>::ProverKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Ws: &[impl Borrow<Self::RW>; M],
        Us: &[impl Borrow<Self::RU>; M],
        ws: &[impl Borrow<Self::IW>; N],
        us: &[impl Borrow<Self::IU>; N],
        rng: impl RngCore,
    ) -> Result<(Self::RW, Self::RU, Self::Proof<M, N>, Self::Challenge), Error>;
}

pub trait FoldingSchemeVerifier<const M: usize, const N: usize>: FoldingSchemeDef {
    #[allow(non_snake_case)]
    fn verify(
        vk: &<Self::DeciderKey as DeciderKey>::VerifierKey,
        transcript: &mut impl Transcript<Self::TranscriptField>,
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, Error>;
}

pub trait FoldingSchemeDecider: FoldingSchemeDef {
    #[allow(non_snake_case)]
    fn decide_running(dk: &Self::DeciderKey, W: &Self::RW, U: &Self::RU) -> Result<(), Error> {
        Relation::<Self::RW, Self::RU>::check_relation(dk, W, U)
    }

    fn decide_incoming(dk: &Self::DeciderKey, w: &Self::IW, u: &Self::IU) -> Result<(), Error> {
        Relation::<Self::IW, Self::IU>::check_relation(dk, w, u)
    }
}

impl<FS: FoldingSchemeDef> FoldingSchemeDecider for FS {}

pub trait FoldingSchemeOps<const M: usize, const N: usize>:
    FoldingSchemePreprocessor
    + FoldingSchemeKeyGenerator
    + FoldingSchemeProver<M, N>
    + FoldingSchemeVerifier<M, N>
    + FoldingSchemeDecider
{
}

impl<FS, const M: usize, const N: usize> FoldingSchemeOps<M, N> for FS where
    FS: FoldingSchemePreprocessor
        + FoldingSchemeKeyGenerator
        + FoldingSchemeProver<M, N>
        + FoldingSchemeVerifier<M, N>
        + FoldingSchemeDecider
{
}
