use ark_r1cs_std::boolean::Boolean;
use ark_std::marker::PhantomData;
use sonobe_primitives::{
    arithmetizations::r1cs::R1CS,
    commitments::{CommitmentDef, CommitmentDefGadget, GroupBasedCommitment},
    traits::{CF2, SonobeField},
};

use self::{
    instances::{
        IncomingInstance as IU, RunningInstance as RU,
        circuits::{IncomingInstanceVar as IUVar, RunningInstanceVar as RUVar},
    },
    witnesses::{IncomingWitness as IW, RunningWitness as RW},
};
use crate::{
    FoldingSchemeDef, FoldingSchemeDefGadget, GroupBasedFoldingSchemePrimaryDef,
    GroupBasedFoldingSchemeSecondaryDef, nova::keys::NovaKey,
};

pub mod algorithms;
pub mod circuits;
pub mod instances;
pub mod keys;
pub mod witnesses;

pub struct AbstractNova<CM, TF, const CHALLENGE_BITS: usize = 128> {
    _t: PhantomData<(CM, TF)>,
}

pub type Nova<CM, const CHALLENGE_BITS: usize = 128> =
    AbstractNova<CM, <CM as CommitmentDef>::Scalar, CHALLENGE_BITS>;

pub type CycleFoldNova<CM, const CHALLENGE_BITS: usize = 128> =
    AbstractNova<CM, CF2<<CM as CommitmentDef>::Commitment>, CHALLENGE_BITS>;

impl<CM: GroupBasedCommitment, TF: SonobeField, const CHALLENGE_BITS: usize> FoldingSchemeDef
    for AbstractNova<CM, TF, CHALLENGE_BITS>
{
    type CM = CM;
    type RW = RW<CM>;
    type RU = RU<CM>;
    type IW = IW<CM>;
    type IU = IU<CM>;

    type TranscriptField = TF;
    type Arith = R1CS<CM::Scalar>;

    type Config = usize;
    type PublicParam = CM::Key;
    type DeciderKey = NovaKey<Self::Arith, CM>;
    type Challenge = [bool; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = CM::Commitment;
}

pub struct AbstractNovaGadget<CM, const CHALLENGE_BITS: usize = 128> {
    _vc: PhantomData<CM>,
}

impl<CM, const CHALLENGE_BITS: usize> FoldingSchemeDefGadget
    for AbstractNovaGadget<CM, CHALLENGE_BITS>
where
    CM: CommitmentDefGadget<Widget: GroupBasedCommitment>,
{
    type Widget = AbstractNova<CM::Widget, CM::ConstraintField, CHALLENGE_BITS>;

    type CM = CM;
    type RU = RUVar<CM>;
    type IU = IUVar<CM>;
    type VerifierKey = ();
    type Challenge = [Boolean<CM::ConstraintField>; CHALLENGE_BITS];
    type Proof<const M: usize, const N: usize> = CM::CommitmentVar;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemePrimaryDef
    for AbstractNova<CM, CM::Scalar, CHALLENGE_BITS>
{
    type Gadget = AbstractNovaGadget<CM::Gadget2, CHALLENGE_BITS>;
}

impl<CM: GroupBasedCommitment, const CHALLENGE_BITS: usize> GroupBasedFoldingSchemeSecondaryDef
    for AbstractNova<CM, CF2<CM::Commitment>, CHALLENGE_BITS>
{
    type Gadget = AbstractNovaGadget<CM::Gadget1, CHALLENGE_BITS>;
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_ff::UniformRand;
    use ark_std::{
        error::Error,
        rand::{RngCore, thread_rng},
    };
    use sonobe_primitives::{
        circuits::utils::{CircuitForTest, satisfying_assignments_for_test},
        commitments::pedersen::Pedersen,
    };
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::tests::test_folding_scheme;

    fn run_nova_configs<TF: SonobeField>(
        rounds: usize,
        mut rng: impl RngCore,
    ) -> Result<(), Box<dyn Error>> {
        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, true>, TF>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, false>, TF>, 1, 1>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, true>, TF>, 2, 0>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;

        test_folding_scheme::<AbstractNova<Pedersen<G1Projective, false>, TF>, 2, 0>(
            8,
            CircuitForTest {
                x: Fr::rand(&mut rng),
            },
            (0..rounds)
                .map(|_| satisfying_assignments_for_test(Fr::rand(&mut rng)))
                .collect(),
            &mut rng,
        )?;
        Ok(())
    }

    #[test]
    fn test_nova() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();

        run_nova_configs::<Fr>(10, &mut rng)?;
        run_nova_configs::<Fq>(10, &mut rng)?;
        Ok(())
    }
}
