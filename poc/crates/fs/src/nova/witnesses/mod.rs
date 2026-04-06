use sonobe_primitives::{arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy};

use crate::FoldingWitness;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningWitness<CM: CommitmentDef> {
    pub e: Vec<CM::Scalar>,
    pub r_e: CM::Randomness,
    pub w: Vec<CM::Scalar>,
    pub r_w: CM::Randomness,
}

impl<CM: CommitmentDef> FoldingWitness<CM> for RunningWitness<CM> {
    const N_OPENINGS: usize = 2;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)> {
        vec![(&self.e, &self.r_e), (&self.w, &self.r_w)]
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for RunningWitness<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            e: vec![Default::default(); cfg.n_constraints()],
            r_e: Default::default(),
            w: vec![Default::default(); cfg.n_witnesses()],
            r_w: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingWitness<CM: CommitmentDef> {
    pub w: Vec<CM::Scalar>,
    pub r_w: CM::Randomness,
}

impl<CM: CommitmentDef> FoldingWitness<CM> for IncomingWitness<CM> {
    const N_OPENINGS: usize = 1;

    fn openings(&self) -> Vec<(&[CM::Scalar], &CM::Randomness)> {
        vec![(&self.w, &self.r_w)]
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for IncomingWitness<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            w: vec![Default::default(); cfg.n_witnesses()],
            r_w: Default::default(),
        }
    }
}
