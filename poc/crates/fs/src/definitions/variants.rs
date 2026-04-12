use sonobe_primitives::{
    commitments::{CommitmentDef, GroupBasedCommitment},
    traits::CF2,
};

use crate::{
    FoldingScheme, FoldingSchemeDef, FoldingSchemeDefGadget, FoldingSchemeFullVerifierGadget,
    FoldingSchemePartialVerifierGadget,
};

/// Group-based folding scheme whose transcript stays in the commitment scalar field.
///
/// Its verifier surface only needs partial in-circuit fold verification.
pub trait GroupBasedFoldingSchemePrimaryDef:
    FoldingSchemeDef<
    CM: GroupBasedCommitment,
    TranscriptField = <<Self as FoldingSchemeDef>::CM as CommitmentDef>::Scalar,
>
{
    /// In-circuit verifier surface paired with this primary scheme.
    type Verifier: FoldingSchemeDefGadget<
        Scheme = Self,
        CM = <Self::CM as GroupBasedCommitment>::Gadget2,
    >;
}

/// Fully configured primary group-based folding scheme for a given fold arity.
pub trait GroupBasedFoldingSchemePrimary<const M: usize, const N: usize>:
    GroupBasedFoldingSchemePrimaryDef<Verifier: FoldingSchemePartialVerifierGadget<M, N>>
    + FoldingScheme<M, N>
{
}

impl<FS, const M: usize, const N: usize> GroupBasedFoldingSchemePrimary<M, N> for FS where
    FS: GroupBasedFoldingSchemePrimaryDef<Verifier: FoldingSchemePartialVerifierGadget<M, N>>
        + FoldingScheme<M, N>
{
}

/// Group-based folding scheme whose transcript lives in the commitment base field.
///
/// Its verifier surface fully checks each in-circuit fold step.
pub trait GroupBasedFoldingSchemeSecondaryDef:
    FoldingSchemeDef<
    CM: GroupBasedCommitment,
    TranscriptField = CF2<<<Self as FoldingSchemeDef>::CM as CommitmentDef>::Commitment>,
>
{
    /// In-circuit verifier surface paired with this secondary scheme.
    type Verifier: FoldingSchemeDefGadget<
        Scheme = Self,
        CM = <Self::CM as GroupBasedCommitment>::Gadget1,
    >;
}

/// Fully configured secondary group-based folding scheme for a given fold arity.
pub trait GroupBasedFoldingSchemeSecondary<const M: usize, const N: usize>:
    GroupBasedFoldingSchemeSecondaryDef<Verifier: FoldingSchemeFullVerifierGadget<M, N>>
    + FoldingScheme<M, N>
{
}

impl<FS, const M: usize, const N: usize> GroupBasedFoldingSchemeSecondary<M, N> for FS where
    FS: GroupBasedFoldingSchemeSecondaryDef<Verifier: FoldingSchemeFullVerifierGadget<M, N>>
        + FoldingScheme<M, N>
{
}
