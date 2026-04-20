use ark_std::rand::RngCore;
use sonobe_primitives::{commitments::GroupBasedCommitment, traits::SonobeField};

use crate::{nova::AbstractNova, Error, FoldingSchemePreprocessor};

impl<CM: GroupBasedCommitment, TF: SonobeField, const B: usize> FoldingSchemePreprocessor
    for AbstractNova<CM, TF, B>
{
    fn preprocess(
        commitment_key_len: usize,
        mut rng: impl RngCore,
    ) -> Result<Self::PublicParam, Error> {
        let commitment_key = CM::generate_key(commitment_key_len, &mut rng)?;
        Ok(commitment_key)
    }
}
