//! Implementation of transcript traits for arkworks' Poseidon sponge.

use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge,
    constraints::CryptographicSpongeVar,
    poseidon::{PoseidonConfig, PoseidonSponge, constraints::PoseidonSpongeVar},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

use crate::transcripts::{AbsorbableVar, Transcript, TranscriptGadget};

impl<F: PrimeField + ark_crypto_primitives::sponge::Absorb> Transcript<F> for PoseidonSponge<F> {
    type Config = PoseidonConfig<F>;
    type Gadget = PoseidonSpongeVar<F>;

    fn new(config: &Self::Config) -> Self {
        CryptographicSponge::new(config)
    }

    fn add_field_elements(&mut self, input: &[F]) -> &mut Self {
        CryptographicSponge::absorb(self, &input);
        self
    }

    fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        CryptographicSponge::squeeze_bits(self, num_bits)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_native_field_elements(num_elements)
    }
}

impl<F: PrimeField + ark_crypto_primitives::sponge::Absorb> TranscriptGadget<F>
    for PoseidonSpongeVar<F>
{
    type Widget = PoseidonSponge<F>;

    fn new(config: &PoseidonConfig<F>) -> Self
    where
        Self: Sized,
    {
        CryptographicSpongeVar::new(ConstraintSystemRef::None, config)
    }

    fn add<A: AbsorbableVar<F> + ?Sized>(
        &mut self,
        input: &A,
    ) -> Result<&mut Self, SynthesisError> {
        let mut result = Vec::new();
        input.absorb_into(&mut result)?;

        self.absorb(&result)?;
        Ok(self)
    }

    fn get_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        self.squeeze_bits(num_bits)
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.squeeze_field_elements(num_elements)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Projective as G1, g1::Config};
    use ark_crypto_primitives::sponge::poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar};
    use ark_ff::UniformRand;
    use ark_r1cs_std::{
        GR1CSVar, alloc::AllocVar, fields::fp::FpVar,
        groups::curves::short_weierstrass::ProjectiveVar,
    };
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, rand::thread_rng, str::FromStr};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use crate::{
        algebra::group::emulated::EmulatedAffineVar,
        transcripts::{Transcript, TranscriptGadget, poseidon::poseidon_canonical_config},
    };

    // Test with value taken from https://github.com/iden3/circomlibjs/blob/43cc582b100fc3459cf78d903a6f538e5d7f38ee/test/poseidon.js#L32
    #[test]
    fn check_against_circom_poseidon() -> Result<(), Box<dyn Error>> {
        let config = poseidon_canonical_config::<Fr>();
        let mut poseidon_sponge = PoseidonSponge::new(&config);
        let v = vec![1, 2, 3, 4]
            .into_iter()
            .map(Fr::from)
            .collect::<Vec<_>>();
        poseidon_sponge.add(&v);
        poseidon_sponge.get_field_elements(1);
        assert_eq!(
            poseidon_sponge.state[0],
            Fr::from_str(
                "18821383157269793795438455681495246036402687001665670618754263018637548127333"
            )
            .unwrap()
        );
        Ok(())
    }

    #[test]
    fn test_add_field_elements_matches_direct_poseidon_absorb() -> Result<(), Box<dyn Error>> {
        let config = poseidon_canonical_config::<Fr>();
        let input = [1_u64, 2, 3, 4].map(Fr::from);

        let mut transcript_sponge = PoseidonSponge::<Fr>::new(&config);
        transcript_sponge.add_field_elements(&input);
        let transcript_output = transcript_sponge.get_field_elements(1);

        let mut direct_sponge = PoseidonSponge::<Fr>::new(&config);
        ark_crypto_primitives::sponge::CryptographicSponge::absorb(
            &mut direct_sponge,
            &&input[..],
        );
        let direct_output =
            ark_crypto_primitives::sponge::FieldBasedCryptographicSponge::squeeze_native_field_elements(
                &mut direct_sponge,
                1,
            );

        assert_eq!(transcript_output, direct_output);
        Ok(())
    }

    #[test]
    fn test_challenge_field_element() -> Result<(), Box<dyn Error>> {
        // Create a transcript outside of the circuit
        let config = poseidon_canonical_config::<Fr>();
        let mut tr = PoseidonSponge::<Fr>::new(&config);
        tr.add(&Fr::from(42_u32));
        let c = tr.challenge_field_element();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fr>::new(&config);
        let v = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(42_u32)))?;
        tr_var.add(&v)?;
        let c_var = tr_var.challenge_field_element()?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_challenge_bits() -> Result<(), Box<dyn Error>> {
        let nbits = 128;

        // Create a transcript outside of the circuit
        let config = poseidon_canonical_config::<Fq>();
        let mut tr = PoseidonSponge::<Fq>::new(&config);
        tr.add(&Fq::from(42_u32));
        let c = tr.challenge_bits(nbits);

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fq>::new(&config);
        let v = FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(42_u32)))?;
        tr_var.add(&v)?;
        let c_var = tr_var.challenge_bits(nbits)?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_absorb_canonical_point() -> Result<(), Box<dyn Error>> {
        // Create a transcript outside of the circuit
        let config = poseidon_canonical_config::<Fq>();
        let mut tr = PoseidonSponge::<Fq>::new(&config);
        let rng = &mut thread_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fq>::new(&config);
        let p_var = ProjectiveVar::<Config, FpVar<Fq>>::new_witness(cs, || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }

    #[test]
    fn test_absorb_emulated_point() -> Result<(), Box<dyn Error>> {
        // Create a transcript outside of the circuit
        let config = poseidon_canonical_config::<Fr>();
        let mut tr = PoseidonSponge::<Fr>::new(&config);
        let rng = &mut thread_rng();

        let p = G1::rand(rng);
        tr.add(&p);
        let c = tr.challenge_field_element();

        // Create a transcript inside of the circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut tr_var = PoseidonSpongeVar::<Fr>::new(&config);
        let p_var = EmulatedAffineVar::new_witness(cs, || Ok(p))?;
        tr_var.add(&p_var)?;
        let c_var = tr_var.challenge_field_element()?;

        // Assert that in-circuit and out-of-circuit transcripts return the same
        // challenge
        assert_eq!(c, c_var.value()?);
        Ok(())
    }
}
