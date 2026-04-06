use ark_ff::field_hashers::hash_to_field;
use ark_relations::gr1cs::{ConstraintSystem, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    borrow::Borrow,
    io::{Error as IoError, Write},
    marker::PhantomData,
    rand::RngCore,
};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update},
};
use sonobe_fs::{
    DeciderKey, FoldingInstance, FoldingSchemeDef, FoldingSchemeDefGadget,
    FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary,
};
use sonobe_primitives::{
    algebra::field::emulated::EmulatedFieldVar,
    arithmetizations::Arith,
    circuits::{ArithExtractor, AssignmentsExtractor, FCircuit},
    commitments::CommitmentDef,
    relations::WitnessInstanceSampler,
    traits::{CF1, CF2, Dummy, SonobeCurve},
    transcripts::Transcript,
};

use crate::{
    Error, IVC,
    compilers::cyclefold::circuits::{AugmentedCircuit, CycleFoldCircuit},
};

pub mod adapters;
pub mod circuits;

pub trait FoldingSchemeCycleFoldExt<const M: usize, const N: usize>:
    GroupBasedFoldingSchemePrimary<M, N>
{
    type CFCircuit: CycleFoldCircuit<CF2<<Self::CM as CommitmentDef>::Commitment>>;

    const N_CYCLEFOLDS: usize;

    #[allow(non_snake_case)]
    fn to_cyclefold_circuits(
        Us: &[impl Borrow<Self::RU>; M],
        us: &[impl Borrow<Self::IU>; N],
        proof: &Self::Proof<M, N>,
        rho: Self::Challenge,
    ) -> Vec<Self::CFCircuit>;

    #[allow(non_snake_case, clippy::type_complexity)]
    fn to_cyclefold_inputs(
        Us: [<Self::Gadget as FoldingSchemeDefGadget>::RU; M],
        us: [<Self::Gadget as FoldingSchemeDefGadget>::IU; N],
        UU: <Self::Gadget as FoldingSchemeDefGadget>::RU,
        proof: <Self::Gadget as FoldingSchemeDefGadget>::Proof<M, N>,
        rho: <Self::Gadget as FoldingSchemeDefGadget>::Challenge,
    ) -> Result<
        Vec<
            Vec<
                EmulatedFieldVar<
                    <Self::CM as CommitmentDef>::Scalar,
                    CF2<<Self::CM as CommitmentDef>::Commitment>,
                >,
            >,
        >,
        SynthesisError,
    >;
}

pub struct Key<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef, T>(
    pub FS1::DeciderKey,
    pub FS2::DeciderKey,
    pub T,
);

pub struct Proof<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef>(
    pub FS1::RW,
    pub FS1::RU,
    pub FS1::IW,
    pub FS1::IU,
    pub FS2::RW,
    pub FS2::RU,
);

impl<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef, T> Dummy<&Key<FS1, FS2, T>> for Proof<FS1, FS2> {
    fn dummy(pk: &Key<FS1, FS2, T>) -> Self {
        let cfg1 = pk.0.to_arith_config();
        let cfg2 = pk.1.to_arith_config();
        Self(
            FS1::RW::dummy(cfg1),
            FS1::RU::dummy(cfg1),
            FS1::IW::dummy(cfg1),
            FS1::IU::dummy(cfg1),
            FS2::RW::dummy(cfg2),
            FS2::RU::dummy(cfg2),
        )
    }
}

pub struct CycleFoldBasedIVC<FS1, FS2, T> {
    _d: PhantomData<(FS1, FS2, T)>,
}

struct FoldArtifacts<FS1: FoldingSchemeDef, FS2: FoldingSchemeDef> {
    primary_witness: FS1::RW,
    primary_instance: FS1::RU,
    primary_proof: FS1::Proof<1, 1>,
    cyclefold_instances: Vec<FS2::IU>,
    cyclefold_proofs: Vec<FS2::Proof<1, 1>>,
    cyclefold_witness: FS2::RW,
    cyclefold_instance: FS2::RU,
}

impl<FS1, FS2, T> CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS1::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS2::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    T: Transcript<CF1<<FS1::CM as CommitmentDef>::Commitment>>,
{
    fn extract_secondary_arith() -> Result<FS2::Arith, Error> {
        let cs = ArithExtractor::new();
        cs.run_with_constraint_system(|cs| FS1::CFCircuit::default().enforce_point_rlc(cs))?;
        Ok(cs.into_arith::<FS2::Arith>()?)
    }

    fn stabilize_primary_arith<FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>>(
        hash_config: &T::Config,
        step_circuit: &FC,
        arith2: &FS2::Arith,
    ) -> Result<FS1::Arith, Error> {
        let mut arith1 = FS1::Arith::default();

        loop {
            let new_arith1 = {
                let cs = ArithExtractor::new();
                cs.execute_synthesizer(AugmentedCircuit::<FS1, FS2, FC, T> {
                    hash_config: hash_config.clone(),
                    arith1_config: arith1.config(),
                    arith2_config: arith2.config(),
                    step_circuit,
                })?;
                cs.into_arith::<FS1::Arith>()?
            };
            if new_arith1.config() == arith1.config() {
                return Ok(arith1);
            }
            arith1 = new_arith1;
        }
    }

    fn compute_public_parameter_hash(
        dk1: &FS1::DeciderKey,
        dk2: &FS2::DeciderKey,
        hash_config: &T::Config,
    ) -> Result<<FS1::CM as CommitmentDef>::Scalar, Error> {
        struct HashMarshaller<'a>(&'a mut Shake128);

        impl Write for HashMarshaller<'_> {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
                self.0.update(buf);
                Ok(buf.len())
            }

            #[inline]
            fn flush(&mut self) -> Result<(), IoError> {
                Ok(())
            }
        }

        let mut shake = Shake128::default();
        dk1.serialize_compressed(HashMarshaller(&mut shake))?;
        dk2.serialize_compressed(HashMarshaller(&mut shake))?;
        hash_config.serialize_compressed(HashMarshaller(&mut shake))?;
        Ok(hash_to_field::<_, _, 128>(&mut shake.finalize_xof()))
    }

    fn initial_fold_artifacts(
        arith1_config: &<FS1::Arith as Arith>::Config,
        arith2_config: &<FS2::Arith as Arith>::Config,
    ) -> FoldArtifacts<FS1, FS2> {
        FoldArtifacts {
            primary_witness: Dummy::dummy(arith1_config),
            primary_instance: Dummy::dummy(arith1_config),
            primary_proof: Dummy::dummy(arith1_config),
            cyclefold_instances: vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS],
            cyclefold_proofs: vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS],
            cyclefold_witness: Dummy::dummy(arith2_config),
            cyclefold_instance: Dummy::dummy(arith2_config),
        }
    }

    fn prove_cyclefold_steps(
        dk2: &FS2::DeciderKey,
        transcript: &mut T,
        cyclefold_running_witness: &FS2::RW,
        cyclefold_running_instance: &FS2::RU,
        cf_circuits: Vec<FS1::CFCircuit>,
        arith2_config: &<FS2::Arith as Arith>::Config,
        rng: &mut impl RngCore,
    ) -> Result<(Vec<FS2::IU>, Vec<FS2::Proof<1, 1>>, FS2::RW, FS2::RU), Error> {
        let mut cyclefold_instances = vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS];
        let mut cyclefold_proofs = vec![Dummy::dummy(arith2_config); FS1::N_CYCLEFOLDS];
        let mut cyclefold_witness = Dummy::dummy(arith2_config);
        let mut cyclefold_instance = Dummy::dummy(arith2_config);

        for (index, cf_circuit) in cf_circuits.into_iter().enumerate() {
            let cs = AssignmentsExtractor::new();
            cs.run_with_constraint_system(|cs| cf_circuit.enforce_point_rlc(cs))?;

            let (cf_w, cf_u) = dk2.sample(cs.assignments()?, &mut *rng)?;
            let previous_cyclefold_witness = if index == 0 {
                cyclefold_running_witness
            } else {
                &cyclefold_witness
            };
            let previous_cyclefold_instance = if index == 0 {
                cyclefold_running_instance
            } else {
                &cyclefold_instance
            };

            let (next_cyclefold_witness, next_cyclefold_instance, cyclefold_proof, _) = FS2::prove(
                dk2.to_pk(),
                transcript,
                &[previous_cyclefold_witness],
                &[previous_cyclefold_instance],
                &[&cf_w],
                &[&cf_u],
                &mut *rng,
            )?;

            cyclefold_instances[index] = cf_u;
            cyclefold_proofs[index] = cyclefold_proof;
            cyclefold_witness = next_cyclefold_witness;
            cyclefold_instance = next_cyclefold_instance;
        }

        Ok((
            cyclefold_instances,
            cyclefold_proofs,
            cyclefold_witness,
            cyclefold_instance,
        ))
    }

    fn advance_fold_artifacts(
        dk1: &FS1::DeciderKey,
        dk2: &FS2::DeciderKey,
        transcript: &mut T,
        i: usize,
        current_proof: &Proof<FS1, FS2>,
        arith1_config: &<FS1::Arith as Arith>::Config,
        arith2_config: &<FS2::Arith as Arith>::Config,
        rng: &mut impl RngCore,
    ) -> Result<FoldArtifacts<FS1, FS2>, Error> {
        let mut artifacts = Self::initial_fold_artifacts(arith1_config, arith2_config);
        if i == 0 {
            return Ok(artifacts);
        }

        let Proof(
            running_witness,
            running_instance,
            incoming_witness,
            incoming_instance,
            cyclefold_running_witness,
            cyclefold_running_instance,
        ) = current_proof;

        let (primary_witness, primary_instance, primary_proof, challenge) = FS1::prove(
            dk1.to_pk(),
            transcript,
            &[running_witness],
            &[running_instance],
            &[incoming_witness],
            &[incoming_instance],
            &mut *rng,
        )?;

        let cf_circuits = FS1::to_cyclefold_circuits(
            &[running_instance],
            &[incoming_instance],
            &primary_proof,
            challenge,
        );

        artifacts.primary_witness = primary_witness;
        artifacts.primary_instance = primary_instance;
        artifacts.primary_proof = primary_proof;

        (
            artifacts.cyclefold_instances,
            artifacts.cyclefold_proofs,
            artifacts.cyclefold_witness,
            artifacts.cyclefold_instance,
        ) = Self::prove_cyclefold_steps(
            dk2,
            transcript,
            cyclefold_running_witness,
            cyclefold_running_instance,
            cf_circuits,
            arith2_config,
            rng,
        )?;

        Ok(artifacts)
    }
}

impl<FS1, FS2, T> IVC for CycleFoldBasedIVC<FS1, FS2, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS1::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Arith: From<ConstraintSystem<CF1<<FS2::CM as CommitmentDef>::Commitment>>>,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    T: Transcript<CF1<<FS1::CM as CommitmentDef>::Commitment>>,
{
    type Field = <FS1::CM as CommitmentDef>::Scalar;

    type Config = (FS1::Config, FS2::Config, T::Config);

    type PublicParam = (FS1::PublicParam, FS2::PublicParam, T::Config);

    type ProverKey<FC> = Key<FS1, FS2, (T::Config, Self::Field)>;

    type VerifierKey<FC> = Key<FS1, FS2, (T::Config, Self::Field)>;

    type Proof<FC> = Proof<FS1, FS2>;

    fn preprocess(
        (cfg1, cfg2, hash_config): Self::Config,
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        Ok((
            FS1::preprocess(cfg1, &mut rng)?,
            FS2::preprocess(cfg2, &mut rng)?,
            hash_config,
        ))
    }

    fn generate_keys<FC: FCircuit<Field = Self::Field>>(
        (pp1, pp2, hash_config): Self::PublicParam,
        step_circuit: &FC,
    ) -> Result<(Self::ProverKey<FC>, Self::VerifierKey<FC>), Error> {
        let arith2 = Self::extract_secondary_arith()?;
        let arith1 = Self::stabilize_primary_arith(&hash_config, step_circuit, &arith2)?;
        let dk1 = FS1::generate_keys(pp1, arith1)?;
        let dk2 = FS2::generate_keys(pp2, arith2)?;
        let pp_hash = Self::compute_public_parameter_hash(&dk1, &dk2, &hash_config)?;

        Ok((
            Key(dk1.clone(), dk2.clone(), (hash_config.clone(), pp_hash)),
            Key(dk1, dk2, (hash_config, pp_hash)),
        ))
    }

    #[allow(non_snake_case)]
    fn prove<FC: FCircuit<Field = Self::Field>>(
        Key(dk1, dk2, (hash_config, pp_hash)): &Self::ProverKey<FC>,
        step_circuit: &FC,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        external_inputs: FC::ExternalInputs,
        current_proof: &Self::Proof<FC>,
        mut rng: impl RngCore,
    ) -> Result<(FC::State, FC::ExternalOutputs, Self::Proof<FC>), Error> {
        let hash = T::new_with_public_parameter_hash(hash_config, *pp_hash);
        let mut transcript = hash.separate_domain("transcript".as_ref());

        let arith1_config = dk1.to_arith_config();
        let arith2_config = dk2.to_arith_config();
        let FoldArtifacts {
            primary_witness,
            primary_instance,
            primary_proof,
            cyclefold_instances,
            cyclefold_proofs,
            cyclefold_witness,
            cyclefold_instance,
        } = Self::advance_fold_artifacts(
            dk1,
            dk2,
            &mut transcript,
            i,
            current_proof,
            arith1_config,
            arith2_config,
            &mut rng,
        )?;
        let Proof(_, U, _, u, _, cf_U) = current_proof;
        let cs = AssignmentsExtractor::new();
        let (next_state, external_outputs) = cs.run_with_constraint_system(|cs| {
            let augmented_circuit = AugmentedCircuit::<FS1, FS2, FC, T> {
                hash_config: hash_config.clone(),
                arith1_config,
                arith2_config,
                step_circuit,
            };
            augmented_circuit.compute_next_state(
                cs,
                *pp_hash,
                i,
                initial_state,
                current_state,
                external_inputs,
                U,
                u,
                primary_proof,
                cf_U,
                cyclefold_instances,
                cyclefold_proofs,
            )
        })?;
        let (ww, uu) = dk1.sample(cs.assignments()?, &mut rng)?;

        Ok((
            next_state,
            external_outputs,
            Proof(
                primary_witness,
                primary_instance,
                ww,
                uu,
                cyclefold_witness,
                cyclefold_instance,
            ),
        ))
    }

    #[allow(non_snake_case)]
    fn verify<FC: FCircuit<Field = Self::Field>>(
        Key(dk1, dk2, (hash_config, pp_hash)): &Self::VerifierKey<FC>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        Proof(W, U, w, u, cf_W, cf_U): &Self::Proof<FC>,
    ) -> Result<(), Error> {
        if i == 0 {
            return (initial_state == current_state)
                .then_some(())
                .ok_or(Error::IVCVerificationFail);
        }

        let hash = T::new_with_public_parameter_hash(hash_config, *pp_hash);
        let mut sponge = hash.separate_domain("sponge".as_ref());

        let u_x = sponge
            .add(&i)
            .add(initial_state)
            .add(current_state)
            .add(U)
            .add(cf_U)
            .get_field_element();

        if u.public_inputs() != [u_x] {
            return Err(Error::IVCVerificationFail);
        }

        FS1::decide_running(dk1, W, U)?;
        FS1::decide_incoming(dk1, w, u)?;
        FS2::decide_running(dk2, cf_W, cf_U)?;

        Ok(())
    }
}
