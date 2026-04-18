#![warn(missing_docs)]

//! Public folding-scheme contracts and the bundled Nova implementation.
//!
//! The root surface keeps the host-side and gadget-side contracts from
//! [`definitions`] close to the concrete Nova types from [`nova`] so downstream
//! crates can depend on a single entry point.

pub mod definitions;
pub mod nova;

pub use self::definitions::algorithms::{
    FoldStep, FoldingScheme, FoldingSchemeDecider, FoldingSchemeKeyGenerator, FoldingSchemeOps,
    FoldingSchemePreprocessor, FoldingSchemeProver, FoldingSchemeVerifier,
};
pub use self::definitions::circuits::{
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget, PartialVerifierStep,
};
pub use self::definitions::errors::Error;
pub use self::definitions::instances::{
    FoldingInstance, FoldingInstanceVar, PlainInstance, PlainInstanceVar,
};
pub use self::definitions::keys::DeciderKey;
pub use self::definitions::variants::{
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondary, GroupBasedFoldingSchemeSecondaryDef,
};
pub use self::definitions::witnesses::{
    FoldingWitness, FoldingWitnessVar, PlainWitness, PlainWitnessVar,
};
pub use self::definitions::{FoldingSchemeDef, FoldingSchemeDefGadget};

#[cfg(test)]
mod tests {
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::{error::Error, rand::Rng, sync::Arc};
    use sonobe_primitives::{
        circuits::{ArithExtractor, AssignmentsOwned},
        commitments::CommitmentDef,
        relations::WitnessInstanceSampler,
        transcripts::{
            griffin::{sponge::GriffinSponge, GriffinParams},
            Transcript,
        },
    };

    use super::*;

    fn sample_running_pool<FS: FoldingSchemeDecider, const M: usize>(
        dk: &FS::DeciderKey,
        rng: &mut impl Rng,
    ) -> Result<([FS::RW; M], [FS::RU; M]), Box<dyn Error>> {
        let mut running_witnesses = vec![];
        let mut running_instances = vec![];
        for _ in 0..M {
            let (running_witness, running_instance) =
                WitnessInstanceSampler::<FS::RW, FS::RU>::sample(dk, (), &mut *rng)?;
            FS::decide_running(dk, &running_witness, &running_instance)?;
            running_witnesses.push(running_witness);
            running_instances.push(running_instance);
        }
        Ok((
            running_witnesses.try_into().unwrap(),
            running_instances.try_into().unwrap(),
        ))
    }

    fn sample_incoming_pool<FS: FoldingSchemeDecider, const N: usize>(
        dk: &FS::DeciderKey,
        assignments: AssignmentsOwned<<FS::CM as CommitmentDef>::Scalar>,
        rng: &mut impl Rng,
    ) -> Result<([FS::IW; N], [FS::IU; N]), Box<dyn Error>> {
        let mut incoming_witnesses = vec![];
        let mut incoming_instances = vec![];
        for _ in 0..N {
            let (incoming_witness, incoming_instance) =
                WitnessInstanceSampler::<FS::IW, FS::IU>::sample(
                    dk,
                    assignments.clone(),
                    &mut *rng,
                )?;
            FS::decide_incoming(dk, &incoming_witness, &incoming_instance)?;
            incoming_witnesses.push(incoming_witness);
            incoming_instances.push(incoming_instance);
        }
        Ok((
            incoming_witnesses.try_into().unwrap(),
            incoming_instances.try_into().unwrap(),
        ))
    }

    fn resample_running_pool<FS: FoldingSchemeDecider, const M: usize>(
        dk: &FS::DeciderKey,
        running_witnesses: &mut [FS::RW; M],
        running_instances: &mut [FS::RU; M],
        rng: &mut impl Rng,
    ) -> Result<(), Box<dyn Error>> {
        for i in 0..M {
            let (running_witness, running_instance) =
                WitnessInstanceSampler::<FS::RW, FS::RU>::sample(dk, (), &mut *rng)?;
            FS::decide_running(dk, &running_witness, &running_instance)?;
            running_witnesses[i] = running_witness;
            running_instances[i] = running_instance;
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
        let public_parameters = FS::preprocess(config, &mut rng)?;

        let cs = ArithExtractor::new();
        cs.execute_synthesizer(circuit)?;
        let arith = cs.into_arith()?;
        let decider_key = FS::generate_keys(public_parameters, arith)?;
        let prover_key = decider_key.prover_key();
        let verifier_key = decider_key.verifier_key();

        let (mut running_witnesses, mut running_instances) =
            sample_running_pool::<FS, M>(&decider_key, &mut rng)?;

        let sponge_config = Arc::new(GriffinParams::new(16, 5, 9));

        let mut prover_transcript = GriffinSponge::new(&sponge_config);
        let mut verifier_transcript = GriffinSponge::new(&sponge_config);

        for assignments in assignments_vec {
            let (incoming_witnesses, incoming_instances) =
                sample_incoming_pool::<FS, N>(&decider_key, assignments, &mut rng)?;

            let FoldStep {
                next_running_witness,
                next_running_instance,
                proof,
                challenge: _challenge,
            } = FS::fold(
                prover_key,
                &mut prover_transcript,
                &running_witnesses,
                &running_instances,
                &incoming_witnesses,
                &incoming_instances,
                &mut rng,
            )?;
            FS::decide_running(&decider_key, &next_running_witness, &next_running_instance)?;
            assert_eq!(
                FS::verify(
                    verifier_key,
                    &mut verifier_transcript,
                    &running_instances,
                    &incoming_instances,
                    &proof,
                )?,
                next_running_instance,
            );

            resample_running_pool::<FS, M>(
                &decider_key,
                &mut running_witnesses,
                &mut running_instances,
                &mut rng,
            )?;
            if M != 0 {
                let idx = rng.gen_range(0..M);
                running_witnesses[idx] = next_running_witness;
                running_instances[idx] = next_running_instance;
            }
        }

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn test_folding_scheme_legacy_prove<
        FS: FoldingScheme<M, N>,
        const M: usize,
        const N: usize,
    >(
        config: FS::Config,
        circuit: impl ConstraintSynthesizer<<FS::CM as CommitmentDef>::Scalar>,
        assignments_vec: Vec<AssignmentsOwned<<FS::CM as CommitmentDef>::Scalar>>,
        mut rng: impl Rng,
    ) -> Result<(), Box<dyn Error>>
    where
        FS::Arith: From<ConstraintSystem<<FS::CM as CommitmentDef>::Scalar>>,
    {
        let public_parameters = FS::preprocess(config, &mut rng)?;

        let cs = ArithExtractor::new();
        cs.execute_synthesizer(circuit)?;
        let arith = cs.into_arith()?;
        let decider_key = FS::generate_keys(public_parameters, arith)?;
        let prover_key = decider_key.prover_key();
        let verifier_key = decider_key.verifier_key();

        let (mut running_witnesses, mut running_instances) =
            sample_running_pool::<FS, M>(&decider_key, &mut rng)?;

        let sponge_config = Arc::new(GriffinParams::new(16, 5, 9));

        let mut prover_transcript = GriffinSponge::new(&sponge_config);
        let mut verifier_transcript = GriffinSponge::new(&sponge_config);

        for assignments in assignments_vec {
            let (incoming_witnesses, incoming_instances) =
                sample_incoming_pool::<FS, N>(&decider_key, assignments, &mut rng)?;

            let (next_running_witness, next_running_instance, proof, _challenge) = FS::prove(
                prover_key,
                &mut prover_transcript,
                &running_witnesses,
                &running_instances,
                &incoming_witnesses,
                &incoming_instances,
                &mut rng,
            )?;
            FS::decide_running(&decider_key, &next_running_witness, &next_running_instance)?;
            assert_eq!(
                FS::verify(
                    verifier_key,
                    &mut verifier_transcript,
                    &running_instances,
                    &incoming_instances,
                    &proof,
                )?,
                next_running_instance,
            );

            resample_running_pool::<FS, M>(
                &decider_key,
                &mut running_witnesses,
                &mut running_instances,
                &mut rng,
            )?;
            if M != 0 {
                let idx = rng.gen_range(0..M);
                running_witnesses[idx] = next_running_witness;
                running_instances[idx] = next_running_instance;
            }
        }

        Ok(())
    }
}
