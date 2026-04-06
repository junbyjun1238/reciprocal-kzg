use ark_ff::PrimeField;
use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};

use crate::traits::SonobeField;

pub mod field;
pub mod group;
pub mod ops;

pub trait Val {
    type PreferredConstraintField: PrimeField;

    type Var: AllocVar<Self, Self::PreferredConstraintField>
        + GR1CSVar<Self::PreferredConstraintField, Value = Self>;

    type EmulatedVar<F: SonobeField>: AllocVar<Self, F> + GR1CSVar<F, Value = Self>;
}
