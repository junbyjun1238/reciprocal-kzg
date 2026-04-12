use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::{fp::FpVar, FieldVar},
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use sonobe_fs::{
    FoldingInstanceVar, FoldingSchemeFullVerifierGadget, FoldingSchemePartialVerifierGadget,
    GroupBasedFoldingSchemePrimary, GroupBasedFoldingSchemeSecondary, PartialVerifierStep,
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
        Verifier: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
        CM: CommitmentDef<Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>>,
    >,
    FS2: GroupBasedFoldingSchemeSecondary<
        1,
        1,
        Verifier: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
        CM: CommitmentDef<Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>>,
    >,
    FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>,
{
    step: FpVar<FC::Field>,
    next_step: FpVar<FC::Field>,
    is_basecase: Boolean<FC::Field>,
    initial_state: FC::StateVar,
    current_state: FC::StateVar,
    running_dummy: <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
    running: <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
    cyclefold_running_dummy: <FS2::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
    cyclefold_running: <FS2::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
    cyclefold_proofs: Vec<<FS2::Verifier as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>>,
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
        Verifier: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
        CM: CommitmentDef<Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>>,
    >,
    FS2: GroupBasedFoldingSchemeSecondary<
        1,
        1,
        Verifier: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
        CM: CommitmentDef<Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>>,
    >,
    FC: FCircuit<Field = <FS1::CM as CommitmentDef>::Scalar>,
    T: Transcript<FC::Field>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn compute_next_state(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        pp_hash: FC::Field,
        i: usize,
        initial_state: &FC::State,
        current_state: &FC::State,
        external_inputs: FC::ExternalInputs,
        running_instance: &FS1::RU,
        incoming_instance: &FS1::IU,
        primary_proof: FS1::Proof<1, 1>,
        cyclefold_running_instance: &FS2::RU,
        cyclefold_incoming_instances: Vec<FS2::IU>,
        cf_proofs: Vec<FS2::Proof<1, 1>>,
    ) -> Result<(FC::State, FC::ExternalOutputs), SynthesisError> {
        let hash = T::Gadget::new_with_public_parameter_hash(
            &self.hash_config,
            &FpVar::new_witness(cs.clone(), || Ok(pp_hash))?,
        )?;
        let sponge = hash.separate_domain("sponge".as_ref())?;
        let mut transcript = hash.separate_domain("transcript".as_ref())?;
        let (inputs, primary_proof_var) = self.allocate_augmented_inputs(
            cs.clone(),
            i,
            initial_state,
            current_state,
            running_instance,
            primary_proof,
            cyclefold_running_instance,
            cf_proofs,
        )?;
        let (incoming_instance_var, next_running_instance, actual_next_running_instance, challenge) =
            self.verify_primary_fold(
                cs.clone(),
                &sponge,
                &mut transcript,
                &inputs,
                &primary_proof_var,
                incoming_instance,
            )?;
        let actual_next_cyclefold_running_instance = self.verify_cyclefold_chain(
            cs.clone(),
            &mut transcript,
            &inputs,
            primary_proof_var,
            cyclefold_incoming_instances,
            incoming_instance_var,
            next_running_instance,
            challenge,
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
            &actual_next_running_instance,
            &actual_next_cyclefold_running_instance,
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
        running_instance: &FS1::RU,
        primary_proof: FS1::Proof<1, 1>,
        cyclefold_running_instance: &FS2::RU,
        cf_proofs: Vec<FS2::Proof<1, 1>>,
    ) -> Result<
        (
            AllocatedAugmentedInputs<FS1, FS2, FC>,
            <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>,
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
                running: AllocVar::new_witness(cs.clone(), || Ok(running_instance))?,
                cyclefold_running_dummy: AllocVar::new_constant(
                    cs.clone(),
                    FS2::RU::dummy(self.arith2_config),
                )?,
                cyclefold_running: AllocVar::new_witness(cs.clone(), || {
                    Ok(cyclefold_running_instance)
                })?,
                cyclefold_proofs: Vec::new_witness(cs.clone(), || Ok(cf_proofs))?,
            },
            AllocVar::new_witness(cs, || Ok(primary_proof))?,
        ))
    }

    fn verify_primary_fold(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        sponge: &T::Gadget,
        transcript: &mut T::Gadget,
        inputs: &AllocatedAugmentedInputs<FS1, FS2, FC>,
        primary_proof: &<FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>,
        incoming_instance: &FS1::IU,
    ) -> Result<
        (
            <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::IU,
            <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
            <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
            <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::Challenge,
        ),
        SynthesisError,
    > {
        let expected_public_input = sponge
            .clone()
            .add(&inputs.step)?
            .add(&inputs.initial_state)?
            .add(&inputs.current_state)?
            .add(&inputs.running)?
            .add(&inputs.cyclefold_running)?
            .get_field_element()?;
        let incoming_instance_var = FoldingInstanceVar::new_witness_with_public_inputs(
            cs,
            incoming_instance,
            vec![expected_public_input],
        )?;
        let PartialVerifierStep {
            next_running_instance,
            challenge,
        } = FS1::Verifier::verify_partial(
            &(),
            transcript,
            [&inputs.running],
            [&incoming_instance_var],
            primary_proof,
        )?;
        let actual_next_running_instance = inputs
            .is_basecase
            .select(&inputs.running_dummy, &next_running_instance)?;
        Ok((
            incoming_instance_var,
            next_running_instance,
            actual_next_running_instance,
            challenge,
        ))
    }

    fn verify_cyclefold_chain(
        &self,
        cs: ConstraintSystemRef<FC::Field>,
        transcript: &mut T::Gadget,
        inputs: &AllocatedAugmentedInputs<FS1, FS2, FC>,
        primary_proof: <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::Proof<1, 1>,
        cyclefold_incoming_instances: Vec<FS2::IU>,
        incoming_instance: <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::IU,
        next_running_instance: <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
        challenge: <FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::Challenge,
    ) -> Result<<FS2::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU, SynthesisError> {
        let mut next_cyclefold_running_instance = inputs.cyclefold_running.clone();
        for ((cyclefold_incoming_instance, cyclefold_public_inputs), cyclefold_proof) in
            cyclefold_incoming_instances
                .iter()
                .zip(FS1::to_cyclefold_inputs(
                    [inputs.running.clone()],
                    [incoming_instance.clone()],
                    next_running_instance,
                    primary_proof,
                    challenge,
                )?)
                .zip(&inputs.cyclefold_proofs)
        {
            let cyclefold_incoming_instance_var =
                FoldingInstanceVar::new_witness_with_public_inputs(
                    cs.clone(),
                    cyclefold_incoming_instance,
                    cyclefold_public_inputs,
                )?;
            next_cyclefold_running_instance = FS2::Verifier::verify(
                &(),
                transcript,
                [&next_cyclefold_running_instance],
                [&cyclefold_incoming_instance_var],
                cyclefold_proof,
            )?;
        }
        inputs.is_basecase.select(
            &inputs.cyclefold_running_dummy,
            &next_cyclefold_running_instance,
        )
    }

    fn mark_next_public_input(
        &self,
        sponge: &T::Gadget,
        next_step: &FpVar<FC::Field>,
        initial_state: &FC::StateVar,
        next_state: &FC::StateVar,
        actual_next_running_instance: &<FS1::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
        actual_next_cyclefold_running_instance: &<FS2::Verifier as sonobe_fs::FoldingSchemeDefGadget>::RU,
    ) -> Result<(), SynthesisError> {
        let next_public_input = sponge
            .clone()
            .add(next_step)?
            .add(initial_state)?
            .add(next_state)?
            .add(actual_next_running_instance)?
            .add(actual_next_cyclefold_running_instance)?
            .get_field_element()?;
        next_public_input.mark_as_public()
    }
}

impl<'a, FS1, FS2, FC, T> ConstraintSynthesizer<FC::Field> for AugmentedCircuit<'a, FS1, FS2, FC, T>
where
    FS1: FoldingSchemeCycleFoldExt<
        1,
        1,
        Verifier: FoldingSchemePartialVerifierGadget<1, 1, VerifierKey = ()>,
        CM: CommitmentDef<Commitment: SonobeCurve<BaseField = <FS2::CM as CommitmentDef>::Scalar>>,
    >,
    FS2: GroupBasedFoldingSchemeSecondary<
        1,
        1,
        Verifier: FoldingSchemeFullVerifierGadget<1, 1, VerifierKey = ()>,
        CM: CommitmentDef<Commitment: SonobeCurve<BaseField = <FS1::CM as CommitmentDef>::Scalar>>,
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
