//! This module defines the core relation traits for generic witness-instance
//! satisfaction checks and satisfying pair generation.
//!
//! These traits are intentionally generic so that different arithmetizations
//! (R1CS, CCS) and different forms (plain, relaxed) can all implement them.

use ark_relations::gr1cs::SynthesisError;
use ark_std::{error::Error, rand::RngCore};

/// [`Relation`] checks whether a witness `W` and an instance `U` satisfy the
/// specified relation.
pub trait Relation<W, U> {
    /// [`Relation::Error`] defines the error type that may occur when checking
    /// the relation.
    type Error: Error;

    /// [`Relation::check_relation`] returns `Ok(())` when `w` and `u` satisfy
    /// `self`, or an error otherwise.
    fn check_relation(&self, w: &W, u: &U) -> Result<(), Self::Error>;
}

/// [`RelationGadget`] is the in-circuit counterpart of [`Relation`].
pub trait RelationGadget<WVar, UVar> {
    /// [`RelationGadget::check_relation`] generates constraints enforcing that
    /// `w` and `u` satisfy the relation.
    fn check_relation(&self, w: &WVar, u: &UVar) -> Result<(), SynthesisError>;
}

/// [`WitnessInstanceSampler`] allows sampling a random witness-instance pair
/// that satisfies the relation.
pub trait WitnessInstanceSampler<W, U> {
    /// [`WitnessInstanceSampler::Source`] defines the type of the source from
    /// which a satisfying pair is sampled.
    type Source;

    /// [`WitnessInstanceSampler::Error`] defines the error type that may occur
    /// when sampling a satisfying pair.
    type Error: Error;

    /// [`WitnessInstanceSampler::sample`] draws a random satisfying pair.
    fn sample(&self, source: Self::Source, rng: impl RngCore) -> Result<(W, U), Self::Error>;
}
