use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, boolean::Boolean, groups::CurveVar};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    algebra::ops::bits::FromBitsGadget,
    commitments::{CommitmentDef, CommitmentDefGadget, GroupBasedCommitment},
    transcripts::TranscriptGadget,
};

use crate::{
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
    nova::AbstractNovaGadget,
    nova::instances::circuits::{IncomingInstanceVar as IUVar, RunningInstanceVar as RUVar},
};

fn squeeze_running_incoming_challenge<CM, const B: usize>(
    transcript: &mut impl TranscriptGadget<CM::ConstraintField>,
    running: &RUVar<CM>,
    u: &IUVar<CM>,
    proof: &CM::CommitmentVar,
) -> Result<(Vec<Boolean<CM::ConstraintField>>, CM::ScalarVar), SynthesisError>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    let rho_bits = transcript
        .add(running)?
        .add(u)?
        .add(proof)?
        .challenge_bits(B)?;
    let rho = CM::ScalarVar::from_bits_le(&rho_bits)?;
    Ok((rho_bits, rho))
}

fn fold_running_incoming_with_hint<CM>(
    running: &RUVar<CM>,
    u: &IUVar<CM>,
    proof: &CM::CommitmentVar,
    rho: &CM::ScalarVar,
) -> Result<RUVar<CM>, SynthesisError>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    Ok(RUVar {
        u: (running.u.clone() + rho)
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?,
        cm_e: {
            let cm_e_cs = running.cm_e.cs().or(proof.cs()).or(rho.cs());
            CM::CommitmentVar::new_witness(cm_e_cs.clone(), || {
                if cm_e_cs.is_in_setup_mode() {
                    return Ok(Default::default());
                }
                let u_cm_e = running.cm_e.value()?;
                let proof_value = proof.value()?;
                let rho_value = rho.value()?;
                Ok(u_cm_e + proof_value * rho_value)
            })?
        },
        cm_w: {
            let cm_w_cs = running.cm_w.cs().or(u.cm_w.cs()).or(rho.cs());
            CM::CommitmentVar::new_witness(cm_w_cs.clone(), || {
                if cm_w_cs.is_in_setup_mode() {
                    return Ok(Default::default());
                }
                let u_cm_w = running.cm_w.value()?;
                let u_witness = u.cm_w.value()?;
                let rho_value = rho.value()?;
                Ok(u_cm_w + u_witness * rho_value)
            })?
        },
        x: running
            .x
            .iter()
            .zip(&u.x)
            .map(|(a, b)| (b.clone() * rho + a).try_into())
            .collect::<Result<_, _>>()
            .map_err(|_| SynthesisError::Unsatisfiable)?,
    })
}

fn squeeze_two_running_challenge<CM, const B: usize>(
    transcript: &mut impl TranscriptGadget<CM::ConstraintField>,
    running_1: &RUVar<CM>,
    running_2: &RUVar<CM>,
    proof: &CM::CommitmentVar,
) -> Result<(Vec<Boolean<CM::ConstraintField>>, CM::ScalarVar), SynthesisError>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    let rho_bits = transcript
        .add(&(running_1, running_2))?
        .add(proof)?
        .challenge_bits(B)?;
    let rho = CM::ScalarVar::from_bits_le(&rho_bits)?;
    Ok((rho_bits, rho))
}

fn fold_two_running_with_hint<CM>(
    running_1: &RUVar<CM>,
    running_2: &RUVar<CM>,
    proof: &CM::CommitmentVar,
    rho: &CM::ScalarVar,
) -> Result<RUVar<CM>, SynthesisError>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    Ok(RUVar {
        u: (running_2.u.clone() * rho + &running_1.u)
            .try_into()
            .map_err(|_| SynthesisError::Unsatisfiable)?,
        cm_e: {
            let cm_e_cs = running_1
                .cm_e
                .cs()
                .or(running_2.cm_e.cs())
                .or(proof.cs())
                .or(rho.cs());
            CM::CommitmentVar::new_witness(cm_e_cs.clone(), || {
                if cm_e_cs.is_in_setup_mode() {
                    return Ok(Default::default());
                }
                let rho_value = rho.value()?;
                let u1_cm_e = running_1.cm_e.value()?;
                let proof_value = proof.value()?;
                let u2_cm_e = running_2.cm_e.value()?;
                Ok(u1_cm_e + proof_value * rho_value + u2_cm_e * rho_value * rho_value)
            })?
        },
        cm_w: {
            let cm_w_cs = running_1.cm_w.cs().or(running_2.cm_w.cs()).or(rho.cs());
            CM::CommitmentVar::new_witness(cm_w_cs.clone(), || {
                if cm_w_cs.is_in_setup_mode() {
                    return Ok(Default::default());
                }
                let u1_cm_w = running_1.cm_w.value()?;
                let u2_cm_w = running_2.cm_w.value()?;
                let rho_value = rho.value()?;
                Ok(u1_cm_w + u2_cm_w * rho_value)
            })?
        },
        x: running_1
            .x
            .iter()
            .zip(&running_2.x)
            .map(|(a, b)| (b.clone() * rho + a).try_into())
            .collect::<Result<_, _>>()
            .map_err(|_| SynthesisError::Unsatisfiable)?,
    })
}

impl<CM, const B: usize> FoldingSchemePartialVerifierGadget<1, 1> for AbstractNovaGadget<CM, B>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<CM::ConstraintField>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let (rho_bits, rho) = squeeze_running_incoming_challenge::<CM, B>(transcript, U, u, proof)?;
        let UU = fold_running_incoming_with_hint(U, u, proof, &rho)?;
        Ok((UU, rho_bits.try_into().unwrap()))
    }
}

impl<CM, const B: usize> FoldingSchemePartialVerifierGadget<2, 0> for AbstractNovaGadget<CM, B>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    #[allow(non_snake_case)]
    fn verify_hinted(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<CM::ConstraintField>,
        [U1, U2]: [&Self::RU; 2],
        _: [&Self::IU; 0],
        proof: &Self::Proof<2, 0>,
    ) -> Result<(Self::RU, Self::Challenge), SynthesisError> {
        let (rho_bits, rho) = squeeze_two_running_challenge::<CM, B>(transcript, U1, U2, proof)?;
        let UU = fold_two_running_with_hint(U1, U2, proof, &rho)?;
        Ok((UU, rho_bits.try_into().unwrap()))
    }
}

impl<CM, const B: usize> FoldingSchemeFullVerifierGadget<1, 1> for AbstractNovaGadget<CM, B>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
    CM::CommitmentVar: CurveVar<<CM::Widget as CommitmentDef>::Commitment, CM::ConstraintField>,
{
    #[allow(non_snake_case)]
    fn verify(
        _vk: &Self::VerifierKey,
        transcript: &mut impl TranscriptGadget<CM::ConstraintField>,
        [U]: [&Self::RU; 1],
        [u]: [&Self::IU; 1],
        proof: &Self::Proof<1, 1>,
    ) -> Result<Self::RU, SynthesisError> {
        let rho_bits = transcript.add(&U)?.add(&u)?.add(proof)?.challenge_bits(B)?;
        let rho = CM::ScalarVar::from_bits_le(&rho_bits)?;

        Ok(Self::RU {
            u: (U.u.clone() + &rho)
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
            cm_e: proof.scalar_mul_le(rho_bits.iter())? + &U.cm_e,
            cm_w: u.cm_w.scalar_mul_le(rho_bits.iter())? + &U.cm_w,
            x: U.x
                .iter()
                .zip(&u.x)
                .map(|(a, b)| (b.clone() * &rho + a).try_into())
                .collect::<Result<_, _>>()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        })
    }
}
