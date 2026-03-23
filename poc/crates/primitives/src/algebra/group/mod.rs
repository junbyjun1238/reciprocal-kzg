//! This module defines extension traits for elliptic curve points and their
//! in-circuit counterparts, along with some common implementations.

use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    short_weierstrass::{Projective, SWCurveConfig},
};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_r1cs_std::{
    convert::ToConstraintFieldGadget,
    fields::fp::FpVar,
    groups::{CurveVar, curves::short_weierstrass::ProjectiveVar},
};
use ark_relations::gr1cs::SynthesisError;

use crate::{
    algebra::{Val, field::SonobeField, group::emulated::EmulatedAffineVar},
    circuits::WitnessToPublic,
    traits::{Dummy, Inputize, InputizeEmulated},
    transcripts::{Absorbable, AbsorbableVar},
};

pub mod emulated;

/// [`CF1`] is a type alias for the scalar field of a curve `C`.
pub type CF1<C> = <C as PrimeGroup>::ScalarField;
/// [`CF2`] is a type alias for the base field of a curve `C`.
pub type CF2<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

/// [`SonobeCurve`] trait is a wrapper around [`CurveGroup`] that also includes
/// necessary bounds for the curve to be used conveniently in folding schemes.
pub trait SonobeCurve:
    CurveGroup<ScalarField: SonobeField, BaseField: SonobeField, Config: SWCurveConfig>
    + Absorbable
    + Inputize<Self::BaseField>
    + InputizeEmulated<Self::ScalarField>
    + Val<
        Var: CurveVar<Self, Self::BaseField> + AbsorbableVar<Self::BaseField> + WitnessToPublic,
        EmulatedVar<Self::ScalarField> = EmulatedAffineVar<Self::ScalarField, Self>,
    >
{
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> SonobeCurve
    for Projective<P>
{
}

impl<P: SWCurveConfig<ScalarField: SonobeField, BaseField: SonobeField>> Val for Projective<P> {
    type PreferredConstraintField = P::BaseField;
    type Var = ProjectiveVar<P, FpVar<P::BaseField>>;

    type EmulatedVar<F: SonobeField> = EmulatedAffineVar<F, Self>;
}

impl<T, C: SonobeCurve> Dummy<T> for C {
    fn dummy(_: T) -> Self {
        Default::default()
    }
}

impl<P: SWCurveConfig<BaseField: Absorbable>> Absorbable for Projective<P> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();
        [x, y].absorb_into(dest);
    }
}

impl<P: SWCurveConfig<BaseField: PrimeField>> AbsorbableVar<P::BaseField>
    for ProjectiveVar<P, FpVar<P::BaseField>>
{
    fn absorb_into(&self, dest: &mut Vec<FpVar<P::BaseField>>) -> Result<(), SynthesisError> {
        let mut vec = self.to_constraint_field()?;
        // The last element in the vector tells whether the point is infinity,
        // but we can in fact avoid absorbing it without loss of soundness.
        // This is because the `to_constraint_field` method internally invokes
        // [`ProjectiveVar::to_afine`](https://github.com/arkworks-rs/r1cs-std/blob/4020fbc22625621baa8125ede87abaeac3c1ca26/src/groups/curves/short_weierstrass/mod.rs#L160-L195),
        // which guarantees that an infinity point is represented as `(0, 0)`,
        // but the y-coordinate of a non-infinity point is never 0 (for why, see
        // https://crypto.stackexchange.com/a/108242 ).
        vec.pop();
        dest.extend(vec);
        Ok(())
    }
}

impl<P: SWCurveConfig<BaseField: SonobeField>> Inputize<P::BaseField> for Projective<P> {
    fn inputize(&self) -> Vec<P::BaseField> {
        let affine = self.into_affine();
        match affine.xy() {
            Some((x, y)) => vec![x, y, One::one()],
            None => vec![Zero::zero(), One::one(), Zero::zero()],
        }
    }
}

impl<P: SWCurveConfig<BaseField: SonobeField, ScalarField: SonobeField>>
    InputizeEmulated<P::ScalarField> for Projective<P>
{
    fn inputize_emulated(&self) -> Vec<P::ScalarField> {
        let affine = self.into_affine();
        let (x, y) = affine.xy().unwrap_or_default();

        [x, y].inputize_emulated()
    }
}

impl<P: SWCurveConfig<BaseField: PrimeField>> WitnessToPublic
    for ProjectiveVar<P, FpVar<P::BaseField>>
{
    fn mark_as_public(&self) -> Result<(), SynthesisError> {
        // We only need the x and y coordinates of the point, but the `infinity`
        // flag is not necessary.
        self.to_constraint_field()?[..2].mark_as_public()
    }
}
