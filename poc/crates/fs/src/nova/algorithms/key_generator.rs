use ark_std::sync::Arc;
use sonobe_primitives::{
    arithmetizations::{Arith, ArithConfig},
    commitments::{CommitmentKey, GroupBasedCommitment},
    traits::SonobeField,
};

use crate::{nova::AbstractNova, Error, FoldingSchemeKeyGenerator};

impl<CM: GroupBasedCommitment, TF: SonobeField, const B: usize> FoldingSchemeKeyGenerator
    for AbstractNova<CM, TF, B>
{
    fn generate_keys(
        commitment_key: Self::PublicParam,
        arith: Self::Arith,
    ) -> Result<Self::DeciderKey, Error> {
        let commitment_key = Arc::new(commitment_key);
        let arith = Arc::new(arith);
        let arith_config = arith.config();
        let required_scalars = arith_config.n_constraints().max(arith_config.n_witnesses());

        if commitment_key.max_scalars_len() < required_scalars {
            return Err(Error::InvalidPublicParameters(
                "The commitment key is too short for the R1CS instance".into(),
            ));
        }

        Ok(Self::DeciderKey {
            arith,
            ck: commitment_key,
        })
    }
}
