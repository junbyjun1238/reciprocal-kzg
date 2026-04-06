use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
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
        let hash = T::Gadget::new_with_pp_hash(
            &self.hash_config,
            &FpVar::new_witness(cs.clone(), || Ok(pp_hash))?,
        )?;
        let sponge = hash.separate_domain("sponge".as_ref())?;
        let mut transcript = hash.separate_domain("transcript".as_ref())?;

        let i = FpVar::new_witness(cs.clone(), || Ok(FC::Field::from(i as u64)))?;
        let ii = &i + FpVar::one();

        let is_basecase = i.is_zero()?;

        let initial_state = FC::StateVar::new_witness(cs.clone(), || Ok(initial_state))?;
        let current_state = FC::StateVar::new_witness(cs.clone(), || Ok(current_state))?;

        let U_dummy = AllocVar::new_constant(cs.clone(), FS1::RU::dummy(self.arith1_config))?;
        let U = AllocVar::new_witness(cs.clone(), || Ok(U))?;
        let proof = AllocVar::new_witness(cs.clone(), || Ok(proof))?;

        let cf_U_dummy = AllocVar::new_constant(cs.clone(), FS2::RU::dummy(self.arith2_config))?;
        let cf_U = AllocVar::new_witness(cs.clone(), || Ok(cf_U))?;
        let cf_proofs = Vec::new_witness(cs.clone(), || Ok(cf_proofs))?;

        let u_x = sponge
            .clone()
            .add(&i)?
            .add(&initial_state)?
            .add(&current_state)?
            .add(&U)?
            .add(&cf_U)?
            .get_field_element()?;
        let u = FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), u, vec![u_x])?;
        let (UU, rho) = FS1::Gadget::verify_hinted(&(), &mut transcript, [&U], [&u], &proof)?;
        let actual_UU = is_basecase.select(&U_dummy, &UU)?;

        let mut cf_UU = cf_U;
        for ((cf_u, cf_u_x), cf_proof) in cf_us
            .iter()
            .zip(FS1::to_cyclefold_inputs([U], [u], UU, proof, rho)?)
            .zip(&cf_proofs)
        {
            let cf_u =
                FoldingInstanceVar::new_witness_with_public_inputs(cs.clone(), cf_u, cf_u_x)?;
            cf_UU = FS2::Gadget::verify(&(), &mut transcript, [&cf_UU], [&cf_u], cf_proof)?;
        }
        let actual_cf_UU = is_basecase.select(&cf_U_dummy, &cf_UU)?;

        let (next_state, external_outputs) =
            self.step_circuit
                .generate_step_constraints(i, current_state, external_inputs)?;

        let uu_x = sponge
            .clone()
            .add(&ii)?
            .add(&initial_state)?
            .add(&next_state)?
            .add(&actual_UU)?
            .add(&actual_cf_UU)?
            .get_field_element()?;
        uu_x.mark_as_public()?;

        if cs.is_in_setup_mode() {
            Ok((self.step_circuit.dummy_state(), external_outputs))
        } else {
            Ok((next_state.value()?, external_outputs))
        }
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
    fn verify_point_rlc(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError>;
}
