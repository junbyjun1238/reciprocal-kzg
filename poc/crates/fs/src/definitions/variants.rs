use sonobe_primitives::{
    commitments::{CommitmentDef, GroupBasedCommitment},
    traits::CF2,
};

use crate::{
    FoldingScheme, FoldingSchemeDef, FoldingSchemeDefGadget, FoldingSchemeFullVerifierGadget,
    FoldingSchemePartialVerifierGadget,
};

pub trait GroupBasedFoldingSchemePrimaryDef:
    FoldingSchemeDef<
        CM: GroupBasedCommitment,
        TranscriptField = <<Self as FoldingSchemeDef>::CM as CommitmentDef>::Scalar,
    >
{
    type Gadget: FoldingSchemeDefGadget<Widget = Self, CM = <Self::CM as GroupBasedCommitment>::Gadget2>;
}

pub trait GroupBasedFoldingSchemePrimary<const M: usize, const N: usize>:
    GroupBasedFoldingSchemePrimaryDef<Gadget: FoldingSchemePartialVerifierGadget<M, N>>
    + FoldingScheme<M, N>
{
}

impl<FS, const M: usize, const N: usize> GroupBasedFoldingSchemePrimary<M, N> for FS where
    FS: GroupBasedFoldingSchemePrimaryDef<Gadget: FoldingSchemePartialVerifierGadget<M, N>>
        + FoldingScheme<M, N>
{
}

pub trait GroupBasedFoldingSchemeSecondaryDef:
    FoldingSchemeDef<
        CM: GroupBasedCommitment,
        TranscriptField = CF2<<<Self as FoldingSchemeDef>::CM as CommitmentDef>::Commitment>,
    >
{
    type Gadget: FoldingSchemeDefGadget<Widget = Self, CM = <Self::CM as GroupBasedCommitment>::Gadget1>;
}

pub trait GroupBasedFoldingSchemeSecondary<const M: usize, const N: usize>:
    GroupBasedFoldingSchemeSecondaryDef<Gadget: FoldingSchemeFullVerifierGadget<M, N>>
    + FoldingScheme<M, N>
{
}

impl<FS, const M: usize, const N: usize> GroupBasedFoldingSchemeSecondary<M, N> for FS where
    FS: GroupBasedFoldingSchemeSecondaryDef<Gadget: FoldingSchemeFullVerifierGadget<M, N>>
        + FoldingScheme<M, N>
{
}
