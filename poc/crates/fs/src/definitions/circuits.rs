use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{commitments::CommitmentDefGadget, transcripts::TranscriptGadget};

use super::FoldingSchemeDefGadget;

pub trait FoldingSchemePartialVerifierGadget<const M: usize, const N: usize>:
    FoldingSchemeDefGadget
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        running_instances: [&Self::RU; M],
        incoming_instances: [&Self::IU; N],
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
        running_instances: [&Self::RU; M],
        incoming_instances: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, SynthesisError>;
}
