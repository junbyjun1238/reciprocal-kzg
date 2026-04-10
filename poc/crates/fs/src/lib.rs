#![warn(missing_docs)]

pub mod definitions;
pub mod nova;

pub use self::definitions::{
    FoldingSchemeDef, FoldingSchemeDefGadget,
    algorithms::{
        FoldStep, FoldingScheme, FoldingSchemeDecider, FoldingSchemeKeyGenerator,
        FoldingSchemeOps, FoldingSchemePreprocessor, FoldingSchemeProver, FoldingSchemeVerifier,
    },
    circuits::{
        FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
        PartialVerifierStep,
    },
    errors::Error,
    instances::{FoldingInstance, FoldingInstanceVar, PlainInstance, PlainInstanceVar},
    keys::DeciderKey,
    utils::TaggedVec,
    variants::{
        GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemePrimaryDef,
        GroupBasedFoldingSchemeSecondary, GroupBasedFoldingSchemeSecondaryDef,
    },
    witnesses::{FoldingWitness, FoldingWitnessVar, PlainWitness, PlainWitnessVar},
};

#[cfg(test)]
mod tests {
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::{error::Error, rand::Rng, sync::Arc};
    use sonobe_primitives::{
        circuits::{ArithExtractor, AssignmentsOwned},
        commitments::CommitmentDef,
        relations::WitnessInstanceSampler,
        transcripts::{
            Transcript,
            griffin::{GriffinParams, sponge::GriffinSponge},
        },
    };

    use super::*;

    fn sample_running_pool<FS: FoldingSchemeDecider, const M: usize>(
        dk: &FS::DeciderKey,
        rng: &mut impl Rng,
    ) -> Result<([FS::RW; M], [FS::RU; M]), Box<dyn Error>> {
        let mut running_ws = vec![];
        let mut running_us = vec![];
        for _ in 0..M {
            let (w, u) = WitnessInstanceSampler::<FS::RW, FS::RU>::sample(dk, (), &mut *rng)?;
            FS::decide_running(dk, &w, &u)?;
            running_ws.push(w);
            running_us.push(u);
        }
        Ok((
            running_ws.try_into().unwrap(),
            running_us.try_into().unwrap(),
        ))
    }

    fn sample_incoming_pool<FS: FoldingSchemeDecider, const N: usize>(
        dk: &FS::DeciderKey,
        assignments: AssignmentsOwned<<FS::CM as CommitmentDef>::Scalar>,
        rng: &mut impl Rng,
    ) -> Result<([FS::IW; N], [FS::IU; N]), Box<dyn Error>> {
        let mut ws = vec![];
        let mut us = vec![];
        for _ in 0..N {
            let (w, u) = WitnessInstanceSampler::<FS::IW, FS::IU>::sample(
                dk,
                assignments.clone(),
                &mut *rng,
            )?;
            FS::decide_incoming(dk, &w, &u)?;
            ws.push(w);
            us.push(u);
        }
        Ok((ws.try_into().unwrap(), us.try_into().unwrap()))
    }

    fn resample_running_pool<FS: FoldingSchemeDecider, const M: usize>(
        dk: &FS::DeciderKey,
        running_ws: &mut [FS::RW; M],
        running_us: &mut [FS::RU; M],
        rng: &mut impl Rng,
    ) -> Result<(), Box<dyn Error>> {
        for i in 0..M {
            let (w, u) = WitnessInstanceSampler::<FS::RW, FS::RU>::sample(dk, (), &mut *rng)?;
            FS::decide_running(dk, &w, &u)?;
            running_ws[i] = w;
            running_us[i] = u;
        }
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn test_folding_scheme<FS: FoldingScheme<M, N>, const M: usize, const N: usize>(
        config: FS::Config,
        circuit: impl ConstraintSynthesizer<<FS::CM as CommitmentDef>::Scalar>,
        assignments_vec: Vec<AssignmentsOwned<<FS::CM as CommitmentDef>::Scalar>>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>>
    where
        FS::Arith: From<ConstraintSystem<<FS::CM as CommitmentDef>::Scalar>>,
    {
        let pp = FS::preprocess(config, &mut rng)?;

        let cs = ArithExtractor::new();
        cs.execute_synthesizer(circuit)?;
        let arith = cs.into_arith()?;
        let dk = FS::generate_keys(pp, arith)?;
        let pk = dk.prover_key();
        let vk = dk.verifier_key();

        let (mut Ws, mut Us) = sample_running_pool::<FS, M>(&dk, &mut rng)?;

        let config = Arc::new(GriffinParams::new(16, 5, 9));

        let mut transcript_p = GriffinSponge::new(&config);
        let mut transcript_v = GriffinSponge::new(&config);

        for assignments in assignments_vec {
            let (ws, us) = sample_incoming_pool::<FS, N>(&dk, assignments, &mut rng)?;

            let FoldStep {
                next_running_witness,
                next_running_instance,
                proof,
                challenge: _challenge,
            } = FS::fold(pk, &mut transcript_p, &Ws, &Us, &ws, &us, &mut rng)?;
            FS::decide_running(&dk, &next_running_witness, &next_running_instance)?;
            assert_eq!(
                FS::verify(vk, &mut transcript_v, &Us, &us, &proof)?,
                next_running_instance,
            );

            resample_running_pool::<FS, M>(&dk, &mut Ws, &mut Us, &mut rng)?;
            if M != 0 {
                let idx = rng.gen_range(0..M);
                Ws[idx] = next_running_witness;
                Us[idx] = next_running_instance;
            }
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn test_folding_scheme_legacy_prove<FS: FoldingScheme<M, N>, const M: usize, const N: usize>(
        config: FS::Config,
        circuit: impl ConstraintSynthesizer<<FS::CM as CommitmentDef>::Scalar>,
        assignments_vec: Vec<AssignmentsOwned<<FS::CM as CommitmentDef>::Scalar>>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>>
    where
        FS::Arith: From<ConstraintSystem<<FS::CM as CommitmentDef>::Scalar>>,
    {
        let pp = FS::preprocess(config, &mut rng)?;

        let cs = ArithExtractor::new();
        cs.execute_synthesizer(circuit)?;
        let arith = cs.into_arith()?;
        let dk = FS::generate_keys(pp, arith)?;
        let pk = dk.prover_key();
        let vk = dk.verifier_key();

        let (mut Ws, mut Us) = sample_running_pool::<FS, M>(&dk, &mut rng)?;

        let config = Arc::new(GriffinParams::new(16, 5, 9));

        let mut transcript_p = GriffinSponge::new(&config);
        let mut transcript_v = GriffinSponge::new(&config);

        for assignments in assignments_vec {
            let (ws, us) = sample_incoming_pool::<FS, N>(&dk, assignments, &mut rng)?;

            let (next_running_witness, next_running_instance, proof, _challenge) =
                FS::prove(pk, &mut transcript_p, &Ws, &Us, &ws, &us, &mut rng)?;
            FS::decide_running(&dk, &next_running_witness, &next_running_instance)?;
            assert_eq!(
                FS::verify(vk, &mut transcript_v, &Us, &us, &proof)?,
                next_running_instance,
            );

            resample_running_pool::<FS, M>(&dk, &mut Ws, &mut Us, &mut rng)?;
            if M != 0 {
                let idx = rng.gen_range(0..M);
                Ws[idx] = next_running_witness;
                Us[idx] = next_running_instance;
            }
        }

        Ok(())
    }
}
