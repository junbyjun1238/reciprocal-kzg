use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sonobe_primitives::arithmetizations::ArithConfig;

pub trait DeciderKey: CanonicalSerialize + CanonicalDeserialize {
    type ProverKey;
    type VerifierKey;
    type ArithConfig: ArithConfig;

    fn to_pk(&self) -> &Self::ProverKey;
    fn to_vk(&self) -> &Self::VerifierKey;
    fn to_arith_config(&self) -> &Self::ArithConfig;
}
