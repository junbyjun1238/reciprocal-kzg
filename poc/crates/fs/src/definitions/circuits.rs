use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{commitments::CommitmentDefGadget, transcripts::TranscriptGadget};

use super::{FoldingSchemeDefGadget, algorithms::FoldingSchemeOps};

pub trait FoldingSchemePartialVerifierGadget<const M: usize, const N: usize>:
    FoldingSchemeDefGadget<Widget: FoldingSchemeOps<M, N>>
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        Us: [&Self::RU; M],
        us: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError>;
}

pub trait FoldingSchemeFullVerifierGadget<const M: usize, const N: usize>:
    FoldingSchemePartialVerifierGadget<M, N>
{
    #[allow(non_snake_case)]
    fn verify(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        Us: [&Self::RU; M],
        us: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, SynthesisError>;
}
