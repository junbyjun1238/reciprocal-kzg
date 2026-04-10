pub mod algorithms;
pub mod circuits;
pub mod errors;
pub mod instances;
pub mod keys;
pub mod utils;
pub mod variants;
pub mod witnesses;

use ark_r1cs_std::{GR1CSVar, alloc::AllocVar};
use sonobe_primitives::{
    arithmetizations::Arith,
    circuits::AssignmentsOwned,
    commitments::{CommitmentDef, CommitmentDefGadget},
    relations::{Relation, WitnessInstanceSampler},
    traits::{Dummy, SonobeField},
};

use self::{
    errors::Error,
    instances::{FoldingInstance, FoldingInstanceVar},
    keys::DeciderKey,
    witnesses::FoldingWitness,
};

/// Host-side contract for a folding scheme.
///
/// This ties together the running and incoming witness/instance types with the
/// arithmetic relation, decider key, and proof material used by a concrete
/// scheme implementation.
pub trait FoldingSchemeDef {
    /// Commitment scheme shared by the host-side witnesses and instances.
    type CM: CommitmentDef<Scalar: SonobeField>;
    /// Running witness carried across fold steps.
    type RW: FoldingWitness<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    /// Running instance carried across fold steps.
    type RU: FoldingInstance<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    /// Incoming witness introduced at the current fold step.
    type IW: FoldingWitness<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
    /// Incoming instance introduced at the current fold step.
    type IU: FoldingInstance<Self::CM> + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;

    /// Field from which transcript challenges are drawn.
    type TranscriptField: SonobeField;
    /// Arithmetic relation checked by the decider.
    type Arith: Arith<Config = <Self::DeciderKey as DeciderKey>::ArithConfig>;
    /// Scheme-specific configuration used by preprocessing and proving.
    type Config;
    /// Public parameters required to set up the scheme.
    type PublicParam;
    /// Key material that samples, proves, and verifies both running and incoming relations.
    type DeciderKey: DeciderKey
        + Clone
        + Relation<Self::RW, Self::RU, Error = Error>
        + Relation<Self::IW, Self::IU, Error = Error>
        + WitnessInstanceSampler<Self::RW, Self::RU, Source = (), Error = Error>
        + WitnessInstanceSampler<
            Self::IW,
            Self::IU,
            Source = AssignmentsOwned<<Self::CM as CommitmentDef>::Scalar>,
            Error = Error,
        >;
    /// Transcript challenge consumed by the fold relation.
    type Challenge;
    /// Proof object emitted by a fold step.
    type Proof<const M: usize, const N: usize>: Clone
        + for<'a> Dummy<&'a <Self::Arith as Arith>::Config>;
}

/// In-circuit contract for verifying a host-side folding scheme.
///
/// This mirrors the host-side scheme surface with gadget types that live inside
/// the verifier circuit.
pub trait FoldingSchemeDefGadget {
    /// Host-side folding scheme represented by this gadget surface.
    type Scheme: FoldingSchemeDef;

    /// Commitment gadget paired with the host-side commitment scheme.
    type CM: CommitmentDefGadget<Widget = <Self::Scheme as FoldingSchemeDef>::CM>;
    /// Gadget-side running instance.
    type RU: FoldingInstanceVar<Self::CM, Value = <Self::Scheme as FoldingSchemeDef>::RU>;
    /// Gadget-side incoming instance.
    type IU: FoldingInstanceVar<Self::CM, Value = <Self::Scheme as FoldingSchemeDef>::IU>;

    /// Verifier-side key material supplied to the gadget verifier.
    type VerifierKey;

    /// Gadget representation of the host-side challenge.
    type Challenge: AllocVar<
            <Self::Scheme as FoldingSchemeDef>::Challenge,
            <Self::CM as CommitmentDefGadget>::ConstraintField,
        > + GR1CSVar<
            <Self::CM as CommitmentDefGadget>::ConstraintField,
            Value = <Self::Scheme as FoldingSchemeDef>::Challenge,
        >;
    /// Gadget representation of the host-side proof object.
    type Proof<const M: usize, const N: usize>: AllocVar<
            <Self::Scheme as FoldingSchemeDef>::Proof<M, N>,
            <Self::CM as CommitmentDefGadget>::ConstraintField,
        > + GR1CSVar<
            <Self::CM as CommitmentDefGadget>::ConstraintField,
            Value = <Self::Scheme as FoldingSchemeDef>::Proof<M, N>,
        >;
}
