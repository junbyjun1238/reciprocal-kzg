use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    boolean::Boolean,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use sonobe_fs::{
    FoldingInstanceVar, FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary,
};
use sonobe_primitives::{
    arithmetizations::Arith,
    circuits::{FCircuit, WitnessToPublic},
    commitments::CommitmentDef,
    traits::{Dummy, SonobeCurve},
    transcripts::{Transcript, TranscriptGadget},
};

use crate::compilers::cyclefold::FoldingSchemeCycleFoldExt;

struct AllocatedAugmentedInputs<FS1, FS2, FC>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>,
{
    step: FpVar<FC::Field>,
    next_step: FpVar<FC::Field>,
    is_basecase: Boolean<FC::Field>,
    initial_state: FC::StateVar,
    current_state: FC::StateVar,
    running_dummy: <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
    running: <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
    cyclefold_running_dummy: <FS2::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
    cyclefold_running: <FS2::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
    cyclefold_proofs: Vec<<FS2::Gadget as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>>,
}

pub struct AugmentedCircuit<
    'a,
    FS1: GroupBasedFoldingSchemePrimary<1, 1>,
    FS2: GroupBasedFoldingSchemeSecondary<1, 1>,
    FC: FCircuit,
    T: Transcript<FC::Field>,
> {
    pub(super) hash_config: T::Config,
    pub(super) arith1_config: &'a <FS1::Arith as Arith>::Config,
    pub(super) arith2_config: &'a <FS2::Arith as Arith>::Config,
    pub(super) step_circuit: &'a FC,
}

impl<'a, FS1, FS2, FC, T> AugmentedCircuit<'a, FS1, FS2, FC, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>,
    T: Transcript<FC::Field>,
{
    #[allow(non_snake_case, clippy::too_many_arguments)]
    pub fn compute_next_state(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        pp_hash: FC::Field,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        external_inputs: FC::ExternalInputs,
        U: &FS1::RU,
        u: &FS1::IU,
        proof: FS1::Proof<1, 1>,
        cf_U: &FS2::RU,
        cf_us: Vec<FS2::IU>,
        cf_proofs: Vec<FS2::Proof<1, 1>>,
    ) -> Result<(FC::State, FC::ExternalOutputs), SynthesisError> {
        let hash = T::Gadget::new_with_public_parameter_hash(
            &self.hash_config,
            &FpVar::new_witness(cs.clone(), || Ok(pp_hash))?,
        )?;
        let sponge = hash.separate_domain("sponge".as_ref())?;
        let mut transcript = hash.separate_domain("transcript".as_ref())?;
        let (inputs, proof) = self.allocate_augmented_inputs(
            cs.clone(),
            i,
            initial_state,
            current_state,
            U,
            proof,
            cf_U,
            cf_proofs,
        )?;
        let (incoming, UU, actual_UU, rho) =
            self.verify_primary_fold(cs.clone(), &sponge, &mut transcript, &inputs, &proof, u)?;
        let actual_cf_UU = self.verify_cyclefold_chain(
            cs.clone(),
            &mut transcript,
            &inputs,
            proof,
            cf_us,
            incoming,
            UU,
            rho,
        )?;
        let AllocatedAugmentedInputs {
            step,
            next_step,
            initial_state,
            current_state,
            ..
        } = inputs;

        let (next_state, external_outputs) =
            self.step_circuit
                .generate_step_constraints(step, current_state, external_inputs)?;

        self.mark_next_public_input(
            &sponge,
            &next_step,
            &initial_state,
            &next_state,
            &actual_UU,
            &actual_cf_UU,
        )?;

        if cs.is_in_setup_mode() {
            Ok((self.step_circuit.dummy_state(), external_outputs))
        } else {
            Ok((next_state.value()?, external_outputs))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn allocate_augmented_inputs(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        running: &FS1::RU,
        proof: FS1::Proof<1, 1>,
        cf_running: &FS2::RU,
        cf_proofs: Vec<FS2::Proof<1, 1>>,
    ) -> Result<
        (
            AllocatedAugmentedInputs<FS1, FS2, FC>,
            <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>,
        ),
        SynthesisError,
    > {
        let step = FpVar::new_witness(cs.clone(), || Ok(FC::Field::from(i as u64)))?;
        let next_step = &step + FpVar::one();
        let is_basecase = step.is_zero()?;

        Ok((
            AllocatedAugmentedInputs {
                step,
                next_step,
                is_basecase,
                initial_state: FC::StateVar::new_witness(cs.clone(), || Ok(initial_state))?,
                current_state: FC::StateVar::new_witness(cs.clone(), || Ok(current_state))?,
                running_dummy: AllocVar::new_constant(
                    cs.clone(),
                    FS1::RU::dummy(self.arith1_config),
                )?,
                running: AllocVar::new_witness(cs.clone(), || Ok(running))?,
                cyclefold_running_dummy: AllocVar::new_constant(
                    cs.clone(),
                    FS2::RU::dummy(self.arith2_config),
                )?,
                cyclefold_running: AllocVar::new_witness(cs.clone(), || Ok(cf_running))?,
                cyclefold_proofs: Vec::new_witness(cs.clone(), || Ok(cf_proofs))?,
            },
            AllocVar::new_witness(cs, || Ok(proof))?,
        ))
    }

    fn verify_primary_fold(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        sponge: &T::Gadget,
        transcript: &mut T::Gadget,
        inputs: &AllocatedAugmentedInputs<FS1, FS2, FC>,
        proof: &<FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>,
        u: &FS1::IU,
    ) -> Result<
        (
            <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::IU,
            <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
            <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
            <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::Challenge,
        ),
        SynthesisError,
    > {
        let u_x = sponge
            .clone()
            .add(&inputs.step)?
            .add(&inputs.initial_state)?
            .add(&inputs.current_state)?
            .add(&inputs.running)?
            .add(&inputs.cyclefold_running)?
            .get_field_element()?;
        let incoming = FoldingInstanceVar::new_witness_with_public_inputs(cs, u, vec![u_x])?;
        let (uu, rho) =
            FS1::Gadget::verify_hinted(&(), transcript, [&inputs.running], [&incoming], proof)?;
        let actual_uu = inputs.is_basecase.select(&inputs.running_dummy, &uu)?;
        Ok((incoming, uu, actual_uu, rho))
    }

    fn verify_cyclefold_chain(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        transcript: &mut T::Gadget,
        inputs: &AllocatedAugmentedInputs<FS1, FS2, FC>,
        proof: <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>,
        cf_us: Vec<FS2::IU>,
        incoming: <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::IU,
        uu: <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
        rho: <FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::Challenge,
    ) -> Result<<FS2::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU, SynthesisError> {
        let mut cf_uu = inputs.cyclefold_running.clone();
        for ((cf_u, cf_u_x), cf_proof) in cf_us
            .iter()
            .zip(FS1::to_cyclefold_inputs(
                [inputs.running.clone()],
                [incoming.clone()],
                uu,
                proof,
                rho,
            )?)
            .zip(&inputs.cyclefold_proofs)
        {
            let cf_u =
                FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), cf_u, cf_u_x)?;
            cf_uu = FS2::Gadget::verify(&(), transcript, [&cf_uu], [&cf_u], cf_proof)?;
        }
        inputs
            .is_basecase
            .select(&inputs.cyclefold_running_dummy, &cf_uu)
    }

    fn mark_next_public_input(
        &self,
        sponge: &T::Gadget,
        next_step: &FpVar<FC::Field>,
        initial_state: &FC::StateVar,
        next_state: &FC::StateVar,
        actual_uu: &<FS1::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
        actual_cf_uu: &<FS2::Gadget as sonobe_fs::FoldingSchemeDefGadget>::RU,
    ) -> Result<(), SynthesisError> {
        let uu_x = sponge
            .clone()
            .add(next_step)?
            .add(initial_state)?
            .add(next_state)?
            .add(actual_uu)?
            .add(actual_cf_uu)?
            .get_field_element()?;
        uu_x.mark_as_public()
    }
}

impl<'a, FS1, FS2, FC, T> ConstraintSynthesizer<FC::Field> for AugmentedCircuit<'a, FS1, FS2, FC, T>
where
    FS1: FoldingSchemeCycleFoldExt<
            1,
            1,
            Gadget: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FS2: GroupBasedFoldingSchemeSecondary<
            1,
            1,
            Gadget: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
            CM: CommitmentDef<
                Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>,
            >,
        >,
    FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>,
    T: Transcript<FC::Field>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<FC::Field>,
    ) -> Result<(), SynthesisError> {
        self.compute_next_state(
            cs,
            Default::default(),
            0,
            &self.step_circuit.dummy_state(),
            &self.step_circuit.dummy_state(),
            self.step_circuit.dummy_external_inputs(),
            &Dummy::dummy(self.arith1_config),
            &Dummy::dummy(self.arith1_config),
            Dummy::dummy(self.arith1_config),
            &Dummy::dummy(self.arith2_config),
            vec![Dummy::dummy(self.arith2_config); FS1::N_CYCLEFOLDS],
            vec![Dummy::dummy(self.arith2_config); FS1::N_CYCLEFOLDS],
        )
        .map(|_| ())
    }
}

pub trait CycleFoldCircuit<F: PrimeField>: Sized + Default {
    fn enforce_point_rlc(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError>;
}
