use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, fields::fp::FpVar};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_std::{
    fmt::Debug,
    ops::{Deref, Index, IndexMut},
};

use crate::transcripts::{Absorbable, AbsorbableVar};

pub mod reciprocal_test;
pub mod utils;

pub trait FCircuit {
    type Field: PrimeField;
    type State: Clone + PartialEq + Absorbable;
    type StateVar: GR1CSVar<Self::Field, Value = Self::State>
        + AllocVar<Self::State, Self::Field>
        + AbsorbableVar<Self::Field>;
    type ExternalInputs;
    type ExternalOutputs;

    fn dummy_state(&self) -> Self::State;

    fn dummy_external_inputs(&self) -> Self::ExternalInputs;

    fn generate_step_constraints(
        &self,
        i: FpVar<Self::Field>,
        state: Self::StateVar,
        external_inputs: Self::ExternalInputs,
    ) -> Result<(Self::StateVar, Self::ExternalOutputs), SynthesisError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Assignments<F, V> {
    pub constant: F,
    pub public: V,
    pub private: V,
}

pub type AssignmentsOwned<F> = Assignments<F, Vec<F>>;

impl<F, V> From<(F, V, V)> for Assignments<F, V> {
    fn from((u, x, w): (F, V, V)) -> Self {
        Self {
            constant: u,
            public: x,
            private: w,
        }
    }
}

impl<F, V: AsRef<[F]>> Index<usize> for Assignments<F, V> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        let public = self.public.as_ref();
        let private = self.private.as_ref();
        if index == 0 {
            &self.constant
        } else if index <= public.len() {
            &public[index - 1]
        } else {
            &private[index - 1 - public.len()]
        }
    }
}

impl<F, V: AsRef<[F]> + AsMut<[F]>> IndexMut<usize> for Assignments<F, V> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let public = self.public.as_mut();
        let private = self.private.as_mut();
        if index == 0 {
            &mut self.constant
        } else if index <= public.len() {
            &mut public[index - 1]
        } else {
            &mut private[index - 1 - public.len()]
        }
    }
}

pub struct ConstraintSystemExt<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool>
{
    cs: ConstraintSystemRef<F>,
}

impl<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool> Deref
    for ConstraintSystemExt<F, ARITH_ENABLED, ASSIGNMENTS_ENABLED>
{
    type Target = ConstraintSystemRef<F>;

    fn deref(&self) -> &Self::Target {
        &self.cs
    }
}

impl<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool>
    ConstraintSystemExt<F, ARITH_ENABLED, ASSIGNMENTS_ENABLED>
{
    pub fn new() -> Self {
        let cs = ConstraintSystem::<F>::new_ref();
        let mode = if ASSIGNMENTS_ENABLED {
            SynthesisMode::Prove {
                construct_matrices: ARITH_ENABLED,
                generate_lc_assignments: ARITH_ENABLED,
            }
        } else {
            SynthesisMode::Setup
        };
        cs.set_mode(mode);
        Self { cs }
    }

    pub fn execute_synthesizer(
        &self,
        circuit: impl ConstraintSynthesizer<F>,
    ) -> Result<(), SynthesisError> {
        self.run_with_constraint_system(|cs| circuit.generate_constraints(cs))
    }

    pub fn run_with_constraint_system<R>(
        &self,
        circuit: impl FnOnce(ConstraintSystemRef<F>) -> Result<R, SynthesisError>,
    ) -> Result<R, SynthesisError> {
        let result = circuit(self.cs.clone())?;
        if ARITH_ENABLED {
            self.cs.finalize();
        }
        Ok(result)
    }
}

impl<F: Field, const ARITH_ENABLED: bool, const ASSIGNMENTS_ENABLED: bool> Default
    for ConstraintSystemExt<F, ARITH_ENABLED, ASSIGNMENTS_ENABLED>
{
    fn default() -> Self {
        Self::new()
    }
}

pub type ArithExtractor<F> = ConstraintSystemExt<F, true, false>;
pub type AssignmentsExtractor<F> = ConstraintSystemExt<F, false, true>;

impl<F: Field> ArithExtractor<F> {
    pub fn into_arith<A: From<ConstraintSystem<F>>>(self) -> Result<A, SynthesisError> {
        Ok(self.cs.into_inner().unwrap().into())
    }
}

impl<F: Field> AssignmentsExtractor<F> {
    pub fn assignments(self) -> Result<Assignments<F, Vec<F>>, SynthesisError> {
        let witness = self.cs.witness_assignment()?.to_vec();
        let instance = self.cs.instance_assignment()?[1..].to_vec();

        Ok((F::one(), instance, witness).into())
    }
}

pub trait WitnessToPublic {
    fn mark_as_public(&self) -> Result<(), SynthesisError>;
}

impl<T: WitnessToPublic> WitnessToPublic for [T] {
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        self.iter().try_for_each(|x| x.mark_as_public())
    }
}
