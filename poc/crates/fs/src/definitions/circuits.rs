use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{commitments::CommitmentDefGadget, transcripts::TranscriptGadget};

use super::FoldingSchemeDefGadget;

/// The output of a partial in-circuit fold verification step.
pub struct PartialVerifierStep<RU, Challenge> {
    /// The running instance obtained after verifying the fold relation.
    pub next_running_instance: RU,
    /// The transcript challenge derived during partial verification.
    pub challenge: Challenge,
}

/// Verifies enough of a fold inside the circuit to recover the next running instance and challenge.
pub trait FoldingSchemePartialVerifierGadget<const M: usize, const N: usize>:
    FoldingSchemeDefGadget
{
    /// Canonical partial-verification API for new gadget implementations and callers.
    fn verify_partial(
        verifying_key: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        running_instances: [&Self::RU; M],
        incoming_instances: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<PartialVerifierStep<Self::RU, Self::Challenge>, SynthesisError>;

    /// Legacy tuple adapter preserved for backward compatibility.
    ///
    /// New code should implement and call [`Self::verify_partial`] instead.
    fn verify_hinted(
        verifying_key: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        running_instances: [&Self::RU; M],
        incoming_instances: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let step = Self::verify_partial(
            verifying_key,
            transcript,
            running_instances,
            incoming_instances,
            proof,
        )?;
        Ok((step.next_running_instance, step.challenge))
    }
}

/// Fully verifies a fold inside the circuit when only the next running instance is needed.
pub trait FoldingSchemeFullVerifierGadget<const M: usize, const N: usize>:
    FoldingSchemePartialVerifierGadget<M, N>
{
    /// Verifies the fold relation and returns the next running instance.
    fn verify(
        verifying_key: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<<Self::CM as CommitmentDefGadget>::ConstraintField>,
        running_instances: [&Self::RU; M],
        incoming_instances: [&Self::IU; N],
        proof: &Self::Proof<M, N>,
    ) -> Result<Self::RU, SynthesisError>;
}
