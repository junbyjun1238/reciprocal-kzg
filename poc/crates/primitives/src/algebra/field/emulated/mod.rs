use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::EqGadget,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{
    borrow::Borrow,
    cmp::{max, min},
    fmt::Debug,
    marker::PhantomData,
    ops::Index,
};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::Signed;

use crate::{
    algebra::{
        field::{SonobeField, TwoStageFieldVar},
        ops::{
            bits::{FromBitsGadget, ToBitsGadgetExt},
            eq::EquivalenceGadget,
            matrix::{MatrixGadget, SparseMatrixVar},
        },
    },
    transcripts::AbsorbableVar,
    utils::assignments::assignment_or_setup,
};

mod alloc;
mod arith;
mod gadgets;
mod ops;

#[cfg(test)]
mod tests;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bounds(pub BigInt, pub BigInt);

impl Bounds {
    pub fn zero() -> Self {
        Self::default()
    }
}

impl Bounds {
    pub fn add(&self, other: &Self) -> Self {
        Self(&self.0 + &other.0, &self.1 + &other.1)
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self(&self.0 - &other.1, &self.1 - &other.0)
    }

    pub fn add_many(limbs: &[Self]) -> Self {
        Self(
            limbs.iter().map(|l| &l.0).sum(),
            limbs.iter().map(|l| &l.1).sum(),
        )
    }

    pub fn mul(&self, other: &Self) -> Self {
        let ll = &self.0 * &other.0;
        let lu = &self.0 * &other.1;
        let ul = &self.1 * &other.0;
        let uu = &self.1 * &other.1;

        Self(
            min(min(&ll, &lu), min(&ul, &uu)).clone(),
            max(max(&ll, &lu), max(&ul, &uu)).clone(),
        )
    }

    pub fn shl(&self, shift: usize) -> Self {
        Self(&self.0 << shift, &self.1 << shift)
    }

    pub fn shr_narrower(&self, shift: usize) -> Self {
        let d = BigInt::from(1u64) << shift;
        Self(self.0.div_ceil(&d), self.1.div_floor(&d))
    }

    pub fn shr_wider(&self, shift: usize) -> Self {
        let d = BigInt::from(1u64) << shift;
        Self(self.0.div_floor(&d), self.1.div_ceil(&d))
    }

    pub fn filter_safe<F: PrimeField>(self) -> Option<Self> {
        let limit = BigInt::from_biguint(Sign::Plus, F::MODULUS_MINUS_ONE_DIV_TWO.into());
        (self.0 >= -&limit && self.1 <= limit && &self.1 - &self.0 <= limit).then_some(self)
    }
}

fn compose<F: SonobeField>(limbs: impl Borrow<[F]>) -> BigInt {
    let mut r = BigInt::zero();

    for &limb in limbs.borrow().iter().rev() {
        r <<= F::BITS_PER_LIMB;
        r += if limb.into_bigint() > F::MODULUS_MINUS_ONE_DIV_TWO {
            BigInt::from_biguint(Sign::Minus, (-limb).into())
        } else {
            BigInt::from_biguint(Sign::Plus, limb.into())
        };
    }
    r
}

#[derive(Debug, Clone)]
pub struct LimbedVar<F: PrimeField, Cfg, const ALIGNED: bool> {
    _cfg: PhantomData<Cfg>,
    pub(crate) limbs: Vec<FpVar<F>>,
    bounds: Vec<Bounds>,
}

pub type EmulatedIntVar<F> = LimbedVar<F, (), true>;
pub type EmulatedFieldVar<Base, Target> = LimbedVar<Base, Target, true>;

impl<F: SonobeField, const ALIGNED: bool> GR1CSVar<F> for LimbedVar<F, (), ALIGNED> {
    type Value = BigInt;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.limbs.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.limbs.value().map(compose)
    }
}

impl<Base: SonobeField, Target: SonobeField, const ALIGNED: bool> GR1CSVar<Base>
    for LimbedVar<Base, Target, ALIGNED>
{
    type Value = Target;

    fn cs(&self) -> ConstraintSystemRef<Base> {
        self.limbs.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let v = compose(self.limbs.value()?);
        bigint_to_field_element(v).ok_or(SynthesisError::Unsatisfiable)
    }
}

fn bigint_to_field_element<F: PrimeField>(v: BigInt) -> Option<F> {
    let (sign, abs) = v.into_parts();
    if abs >= F::MODULUS.into() {
        return None;
    }
    match sign {
        Sign::Plus | Sign::NoSign => Some(F::from(abs)),
        Sign::Minus => Some(-F::from(abs)),
    }
}

impl<F: SonobeField, Cfg, const ALIGNED: bool> LimbedVar<F, Cfg, ALIGNED> {
    pub fn new(limbs: Vec<FpVar<F>>, bounds: Vec<Bounds>) -> Self {
        Self {
            _cfg: PhantomData,
            limbs,
            bounds,
        }
    }

    fn ubound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.1;
        }

        r
    }

    fn lbound(&self) -> BigInt {
        let mut r = BigInt::zero();

        for i in self.bounds.iter().rev() {
            r <<= F::BITS_PER_LIMB;
            r += &i.0;
        }

        r
    }
}

impl<F: SonobeField, Cfg> From<LimbedVar<F, Cfg, true>> for LimbedVar<F, Cfg, false> {
    fn from(v: LimbedVar<F, Cfg, true>) -> Self {
        Self::new(v.limbs, v.bounds)
    }
}
