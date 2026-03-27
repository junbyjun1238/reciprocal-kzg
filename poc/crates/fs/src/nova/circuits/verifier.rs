//! Partial and full in-circuit verifier implementations for Nova.

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, groups::CurveVar};
use ark_relations::gr1cs::SynthesisError;
use sonobe_primitives::{
    algebra::ops::bits::FromBitsGadget,
    commitments::{CommitmentDef, CommitmentDefGadget, GroupBasedCommitment},
    transcripts::TranscriptGadget,
};

use crate::{
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget, nova::AbstractNovaGadget,
};

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
        let rho_bits = transcript.add(&U)?.add(&u)?.add(proof)?.challenge_bits(B)?;
        let rho = CM::ScalarVar::from_bits_le(&rho_bits)?;

        Ok((
            Self::RU {
                u: (U.u.clone() + &rho)
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
                cm_e: {
                    let cm_e_cs = U.cm_e.cs().or(proof.cs()).or(rho.cs());
                    CM::CommitmentVar::new_witness(cm_e_cs.clone(), || {
                        if cm_e_cs.is_in_setup_mode() {
                            return Ok(Default::default());
                        }
                        let u_cm_e = U.cm_e.value()?;
                        let proof_value = proof.value()?;
                        let rho_value = rho.value()?;
                        Ok(u_cm_e + proof_value * rho_value)
                    })?
                },
                cm_w: {
                    let cm_w_cs = U.cm_w.cs().or(u.cm_w.cs()).or(rho.cs());
                    CM::CommitmentVar::new_witness(cm_w_cs.clone(), || {
                        if cm_w_cs.is_in_setup_mode() {
                            return Ok(Default::default());
                        }
                        let u_cm_w = U.cm_w.value()?;
                        let u_witness = u.cm_w.value()?;
                        let rho_value = rho.value()?;
                        Ok(u_cm_w + u_witness * rho_value)
                    })?
                },
                x: U.x
                    .iter()
                    .zip(&u.x)
                    .map(|(a, b)| (b.clone() * &rho + a).try_into())
                    .collect::<Result<_, _>>()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
            },
            rho_bits.try_into().unwrap(),
        ))
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
        let rho_bits = transcript.add(&(U1, U2))?.add(proof)?.challenge_bits(B)?;
        let rho = CM::ScalarVar::from_bits_le(&rho_bits)?;

        Ok((
            Self::RU {
                u: (U2.u.clone() * &rho + &U1.u)
                    .try_into()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
                cm_e: {
                    let cm_e_cs = U1.cm_e.cs().or(U2.cm_e.cs()).or(proof.cs()).or(rho.cs());
                    CM::CommitmentVar::new_witness(cm_e_cs.clone(), || {
                        if cm_e_cs.is_in_setup_mode() {
                            return Ok(Default::default());
                        }
                        let rho_value = rho.value()?;
                        let u1_cm_e = U1.cm_e.value()?;
                        let proof_value = proof.value()?;
                        let u2_cm_e = U2.cm_e.value()?;
                        Ok(u1_cm_e + proof_value * rho_value + u2_cm_e * rho_value * rho_value)
                    })?
                },
                cm_w: {
                    let cm_w_cs = U1.cm_w.cs().or(U2.cm_w.cs()).or(rho.cs());
                    CM::CommitmentVar::new_witness(cm_w_cs.clone(), || {
                        if cm_w_cs.is_in_setup_mode() {
                            return Ok(Default::default());
                        }
                        let u1_cm_w = U1.cm_w.value()?;
                        let u2_cm_w = U2.cm_w.value()?;
                        let rho_value = rho.value()?;
                        Ok(u1_cm_w + u2_cm_w * rho_value)
                    })?
                },
                x: U1
                    .x
                    .iter()
                    .zip(&U2.x)
                    .map(|(a, b)| (b.clone() * &rho + a).try_into())
                    .collect::<Result<_, _>>()
                    .map_err(|_| SynthesisError::Unsatisfiable)?,
            },
            rho_bits.try_into().unwrap(),
        ))
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
