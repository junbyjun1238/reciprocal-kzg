use ark_r1cs_std::{
    boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar, groups::CurveVar,
};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, iter::repeat_with, marker::PhantomData, rand::RngCore};

use super::{CommitmentDef, CommitmentDefGadget, CommitmentKey, CommitmentOps, Error};
use crate::{
    algebra::{field::emulated::EmulatedFieldVar, group::emulated::EmulatedAffineVar},
    commitments::{CommitmentOpsGadget, GroupBasedCommitment},
    traits::{CF1, CF2, SonobeCurve},
    utils::null::Null,
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenKey<C: SonobeCurve, const H: bool> {
    g: Vec<C::Affine>,
    h: C,
}

impl<C: SonobeCurve, const H: bool> CommitmentKey for PedersenKey<C, H> {
    fn max_scalars_len(&self) -> usize {
        self.g.len()
    }
}

impl<C: SonobeCurve, const H: bool> PedersenKey<C, H> {
    fn new(len: usize, mut rng: impl RngCore) -> Self {
        let generators = repeat_with(|| C::rand(&mut rng))
            .take(len.next_power_of_two())
            .collect::<Vec<_>>();
        Self {
            g: C::normalize_batch(&generators),
            h: if H { C::rand(&mut rng) } else { C::zero() },
        }
    }
}

impl<C: SonobeCurve> PedersenKey<C, true> {
    fn commit(&self, v: &[C::ScalarField], r: &C::ScalarField) -> Result<C, Error> {
        if self.g.len() < v.len() {
            return Err(Error::MessageTooLong(self.g.len(), v.len()));
        }
        // use msm_unchecked because we already ensured at the if that generators are long enough
        Ok(C::msm_unchecked(&self.g, v) + self.h.mul(r))
    }
}

impl<C: SonobeCurve> PedersenKey<C, false> {
    fn commit(&self, v: &[C::ScalarField]) -> Result<C, Error> {
        if self.g.len() < v.len() {
            return Err(Error::MessageTooLong(self.g.len(), v.len()));
        }
        // use msm_unchecked because we already ensured at the if that generators are long enough
        Ok(C::msm_unchecked(&self.g, v))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pedersen<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve> CommitmentDef for Pedersen<C, false> {
    const IS_HIDING: bool = false;

    type Key = PedersenKey<C, false>;
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = Null;
}

impl<C: SonobeCurve> CommitmentDef for Pedersen<C, true> {
    const IS_HIDING: bool = true;

    type Key = PedersenKey<C, true>;
    type Scalar = C::ScalarField;
    type Commitment = C;
    type Randomness = C::ScalarField;
}

impl<C: SonobeCurve> GroupBasedCommitment for Pedersen<C, false> {
    type Gadget1 = PedersenGadget<C, false>;
    type Gadget2 = PedersenEmulatedGadget<C, false>;
}

impl<C: SonobeCurve> GroupBasedCommitment for Pedersen<C, true> {
    type Gadget1 = PedersenGadget<C, true>;
    type Gadget2 = PedersenEmulatedGadget<C, true>;
}

impl<C: SonobeCurve> CommitmentOps for Pedersen<C, false> {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<PedersenKey<C, false>, Error> {
        Ok(PedersenKey::new(len, rng))
    }

    fn commit(
        ck: &PedersenKey<C, false>,
        v: &[CF1<C>],
        _rng: impl RngCore,
    ) -> Result<(C, Null), Error> {
        Ok((ck.commit(v)?, Null))
    }

    fn open(ck: &PedersenKey<C, false>, v: &[CF1<C>], _r: &Null, cm: &C) -> Result<(), Error> {
        (&ck.commit(v)? == cm)
            .then_some(())
            .ok_or(Error::CommitmentVerificationFail)
    }
}

impl<C: SonobeCurve> CommitmentOps for Pedersen<C, true> {
    fn generate_key(len: usize, rng: impl RngCore) -> Result<PedersenKey<C, true>, Error> {
        Ok(PedersenKey::new(len, rng))
    }

    fn commit(
        ck: &PedersenKey<C, true>,
        v: &[CF1<C>],
        mut rng: impl RngCore,
    ) -> Result<(C, CF1<C>), Error> {
        let r = C::ScalarField::rand(&mut rng);
        Ok((ck.commit(v, &r)?, r))
    }

    fn open(ck: &PedersenKey<C, true>, v: &[CF1<C>], r: &CF1<C>, cm: &C) -> Result<(), Error> {
        (&(ck.commit(v, r)?) == cm)
            .then_some(())
            .ok_or(Error::CommitmentVerificationFail)
    }
}

#[derive(Clone)]
pub struct PedersenGadget<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve, const H: bool> PedersenGadget<C, H> {
    fn msm(g: &[C::Var], v: &[Vec<Boolean<CF2<C>>>]) -> Result<C::Var, SynthesisError> {
        let mut res = C::Var::zero();
        let n = v.len();
        if n % 2 == 1 {
            res += g[n - 1].scalar_mul_le(v[n - 1].to_bits_le()?.iter())?;
        } else {
            res += g[n - 1].joint_scalar_mul_be(
                &g[n - 2],
                v[n - 1].to_bits_le()?.iter(),
                v[n - 2].to_bits_le()?.iter(),
            )?;
        }
        for i in (1..n - 1).step_by(2) {
            res += g[i - 1].joint_scalar_mul_be(
                &g[i],
                v[i - 1].to_bits_le()?.iter(),
                v[i].to_bits_le()?.iter(),
            )?;
        }
        Ok(res)
    }
}

impl<C: SonobeCurve> CommitmentOpsGadget for PedersenGadget<C, false> {
    fn open(
        ck: &Vec<C::Var>,
        v: &[EmulatedFieldVar<CF2<C>, CF1<C>>],
        _r: &Null,
        cm: &C::Var,
    ) -> Result<(), SynthesisError> {
        Self::msm(
            ck,
            &v.iter()
                .map(|i| i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?,
        )?
        .enforce_equal(cm)
    }
}

impl<C: SonobeCurve> CommitmentOpsGadget for PedersenGadget<C, true> {
    fn open(
        (g, h): &(Vec<C::Var>, C::Var),
        v: &[EmulatedFieldVar<CF2<C>, CF1<C>>],
        r: &EmulatedFieldVar<CF2<C>, CF1<C>>,
        cm: &C::Var,
    ) -> Result<(), SynthesisError> {
        let gv = Self::msm(
            g,
            &v.iter()
                .map(|i| i.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let hr = h.scalar_mul_le(r.to_bits_le()?.iter())?;
        (gv + hr).enforce_equal(cm)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenEmulatedGadget<C: SonobeCurve, const H: bool> {
    _c: PhantomData<C>,
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenGadget<C, false> {
    type ConstraintField = CF2<C>;

    type KeyVar = Vec<C::Var>;

    type ScalarVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type CommitmentVar = C::Var;

    type RandomnessVar = Null;

    type Widget = Pedersen<C, false>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenGadget<C, true> {
    type ConstraintField = CF2<C>;

    type KeyVar = (Vec<C::Var>, C::Var);

    type ScalarVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type CommitmentVar = C::Var;

    type RandomnessVar = EmulatedFieldVar<CF2<C>, CF1<C>>;

    type Widget = Pedersen<C, true>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenEmulatedGadget<C, false> {
    type ConstraintField = CF1<C>;

    type KeyVar = Vec<EmulatedAffineVar<CF1<C>, C>>;

    type ScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = Null;

    type Widget = Pedersen<C, false>;
}

impl<C: SonobeCurve> CommitmentDefGadget for PedersenEmulatedGadget<C, true> {
    type ConstraintField = CF1<C>;

    type KeyVar = (
        Vec<EmulatedAffineVar<CF1<C>, C>>,
        EmulatedAffineVar<CF1<C>, C>,
    );

    type ScalarVar = FpVar<CF1<C>>;

    type CommitmentVar = EmulatedAffineVar<CF1<C>, C>;

    type RandomnessVar = FpVar<CF1<C>>;

    type Widget = Pedersen<C, true>;
}

#[cfg(test)]
mod tests {
    use ark_bn254::G1Projective;
    use ark_std::{
        error::Error,
        rand::{Rng, thread_rng},
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::commitments::tests::test_commitment_correctness;

    #[test]
    fn test_pedersen_commitment() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        for i in 0..10 {
            let len = rng.gen_range((1 << i)..(1 << (i + 1)));
            test_commitment_correctness::<Pedersen<G1Projective, false>>(&mut rng, len)?;
            test_commitment_correctness::<Pedersen<G1Projective, true>>(&mut rng, len)?;
        }
        Ok(())
    }
}
