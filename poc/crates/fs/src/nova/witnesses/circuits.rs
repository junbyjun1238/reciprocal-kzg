use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use sonobe_primitives::commitments::CommitmentDefGadget;

use super::{IncomingWitness, RunningWitness};

#[derive(Debug, PartialEq)]
pub struct RunningWitnessVar<CM: CommitmentDefGadget> {
    pub e: Vec<CM::ScalarVar>,
    pub r_e: CM::RandomnessVar,
    pub w: Vec<CM::ScalarVar>,
    pub r_w: CM::RandomnessVar,
}

impl<CM: CommitmentDefGadget> AllocVar<RunningWitness<CM::Widget>, CM::ConstraintField>
    for RunningWitnessVar<CM>
{
    fn new_variable<T: Borrow<RunningWitness<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let RunningWitness { e, r_e, w, r_w } = v.borrow();
        Ok(Self {
            e: AllocVar::new_variable(cs.clone(), || Ok(&e[..]), mode)?,
            r_e: AllocVar::new_variable(cs.clone(), || Ok(r_e), mode)?,
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r_w: AllocVar::new_variable(cs.clone(), || Ok(r_w), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for RunningWitnessVar<CM> {
    type Value = RunningWitness<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.e
            .cs()
            .or(self.r_e.cs())
            .or(self.w.cs())
            .or(self.r_w.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RunningWitness {
            e: self.e.value()?,
            r_e: self.r_e.value()?,
            w: self.w.value()?,
            r_w: self.r_w.value()?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct IncomingWitnessVar<CM: CommitmentDefGadget> {
    pub w: Vec<CM::ScalarVar>,
    pub r_w: CM::RandomnessVar,
}

impl<CM: CommitmentDefGadget> AllocVar<IncomingWitness<CM::Widget>, CM::ConstraintField>
    for IncomingWitnessVar<CM>
{
    fn new_variable<T: Borrow<IncomingWitness<CM::Widget>>>(
        cs: impl Into<Namespace<CM::ConstraintField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let IncomingWitness { w, r_w } = v.borrow();
        Ok(Self {
            w: AllocVar::new_variable(cs.clone(), || Ok(&w[..]), mode)?,
            r_w: AllocVar::new_variable(cs.clone(), || Ok(r_w), mode)?,
        })
    }
}

impl<CM: CommitmentDefGadget> GR1CSVar<CM::ConstraintField> for IncomingWitnessVar<CM> {
    type Value = IncomingWitness<CM::Widget>;

    fn cs(&self) -> ConstraintSystemRef<CM::ConstraintField> {
        self.w.cs().or(self.r_w.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(IncomingWitness {
            w: self.w.value()?,
            r_w: self.r_w.value()?,
        })
    }
}
