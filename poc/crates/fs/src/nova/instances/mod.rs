use ark_ff::PrimeField;
use sonobe_primitives::{
    arithmetizations::ArithConfig, commitments::CommitmentDef, traits::Dummy,
    transcripts::Absorbable,
};

use crate::FoldingInstance;

pub mod circuits;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningInstance<CM: CommitmentDef> {
    pub cm_e: CM::Commitment,
    pub u: CM::Scalar,
    pub cm_w: CM::Commitment,
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for RunningInstance<CM> {
    const N_COMMITMENTS: usize = 2;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.cm_e, &self.cm_w]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        &mut self.x
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for RunningInstance<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            cm_e: Default::default(),
            u: Default::default(),
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for RunningInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.u.absorb_into(dest);
        self.x.absorb_into(dest);
        self.cm_e.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingInstance<CM: CommitmentDef> {
    pub cm_w: CM::Commitment,
    pub x: Vec<CM::Scalar>,
}

impl<CM: CommitmentDef> FoldingInstance<CM> for IncomingInstance<CM> {
    const N_COMMITMENTS: usize = 1;

    fn commitments(&self) -> Vec<&CM::Commitment> {
        vec![&self.cm_w]
    }

    fn public_inputs(&self) -> &[CM::Scalar] {
        &self.x
    }

    fn public_inputs_mut(&mut self) -> &mut [CM::Scalar] {
        &mut self.x
    }
}

impl<CM: CommitmentDef, Cfg: ArithConfig> Dummy<&Cfg> for IncomingInstance<CM> {
    fn dummy(cfg: &Cfg) -> Self {
        Self {
            cm_w: Default::default(),
            x: vec![Default::default(); cfg.n_public_inputs()],
        }
    }
}

impl<CM: CommitmentDef> Absorbable for IncomingInstance<CM> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.x.absorb_into(dest);
        self.cm_w.absorb_into(dest);
    }
}
