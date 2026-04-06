use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub use self::absorbable::{Absorbable, AbsorbableVar};

pub mod absorbable;
pub mod griffin;
pub mod poseidon;

pub trait Transcript<F: PrimeField>: Clone {
    type Config: Clone + CanonicalSerialize + CanonicalDeserialize;

    type Gadget: TranscriptGadget<F, Widget = Self>;

    fn new(config: &Self::Config) -> Self;

    fn new_with_public_parameter_hash(config: &Self::Config, public_parameter_hash: F) -> Self {
        let mut sponge = Self::new(config);
        sponge.add_field_elements(&[public_parameter_hash]);
        sponge
    }

    fn add<A: Absorbable + ?Sized>(&mut self, input: &A) -> &mut Self {
        let mut elems = Vec::new();
        input.absorb_into(&mut elems);

        self.add_field_elements(&elems)
    }

    fn add_field_elements(&mut self, input: &[F]) -> &mut Self;

    fn get_bits(&mut self, num_bits: usize) -> Vec<bool>;

    fn get_field_element(&mut self) -> F {
        self.get_field_elements(1)[0]
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Vec<F>;

    fn separate_domain(&self, domain: &[u8]) -> Self {
        let mut new_sponge = self.clone();

        let mut input = domain.len().to_le_bytes().to_vec();
        input.extend_from_slice(domain);

        let limbs = input
            .chunks(F::MODULUS_BIT_SIZE.div_ceil(8) as usize)
            .map(|chunk| F::from_le_bytes_mod_order(chunk))
            .collect::<Vec<_>>();

        new_sponge.add_field_elements(&limbs);

        new_sponge
    }

    fn challenge_field_element(&mut self) -> F {
        let c = self.get_field_elements(1);
        self.add_field_elements(&c);
        c[0]
    }

    fn challenge_bits(&mut self, nbits: usize) -> Vec<bool> {
        let bits = self.get_bits(nbits);
        self.add_field_elements(
            &bits
                .chunks(F::MODULUS_BIT_SIZE as usize - 1)
                .map(F::BigInt::from_bits_le)
                .map(F::from)
                .collect::<Vec<_>>(),
        );
        bits
    }

    fn challenge_field_elements(&mut self, n: usize) -> Vec<F> {
        let c = self.get_field_elements(n);
        self.add_field_elements(&c);
        c
    }
}

pub trait TranscriptGadget<F: PrimeField>: Clone {
    type Widget: Transcript<F, Gadget = Self>;

    fn new(config: &<Self::Widget as Transcript<F>>::Config) -> Self;

    fn new_with_public_parameter_hash(
        config: &<Self::Widget as Transcript<F>>::Config,
        public_parameter_hash: &FpVar<F>,
    ) -> Result<Self, SynthesisError> {
        let mut sponge = Self::new(config);
        sponge.add(public_parameter_hash)?;
        Ok(sponge)
    }

    fn add<A: AbsorbableVar<F> + ?Sized>(&mut self, input: &A)
    -> Result<&mut Self, SynthesisError>;

    fn get_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;

    fn get_field_element(&mut self) -> Result<FpVar<F>, SynthesisError> {
        Ok(self.get_field_elements(1)?.swap_remove(0))
    }

    fn get_field_elements(&mut self, num_elements: usize) -> Result<Vec<FpVar<F>>, SynthesisError>;

    fn separate_domain(&self, domain: &[u8]) -> Result<Self, SynthesisError> {
        let mut new_sponge = self.clone();

        let mut input = domain.len().to_le_bytes().to_vec();
        input.extend_from_slice(domain);

        let limbs = input
            .chunks(F::MODULUS_BIT_SIZE.div_ceil(8) as usize)
            .map(|chunk| FpVar::Constant(F::from_le_bytes_mod_order(chunk)))
            .collect::<Vec<_>>();

        new_sponge.add(&limbs)?;

        Ok(new_sponge)
    }

    fn challenge_field_element(&mut self) -> Result<FpVar<F>, SynthesisError> {
        let mut c = self.get_field_elements(1)?;
        self.add(&c[0])?;
        Ok(c.swap_remove(0))
    }

    fn challenge_bits(&mut self, nbits: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let bits = self.get_bits(nbits)?;
        self.add(
            &bits
                .chunks(F::MODULUS_BIT_SIZE as usize - 1)
                .map(Boolean::le_bits_to_fp)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        Ok(bits)
    }

    fn challenge_field_elements(&mut self, n: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let c = self.get_field_elements(n)?;
        self.add(&c)?;
        Ok(c)
    }
}
