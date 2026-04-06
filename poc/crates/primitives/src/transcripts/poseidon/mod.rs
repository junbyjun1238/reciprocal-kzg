use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_ff::PrimeField;

pub mod sponge;

pub fn poseidon_custom_config<F: PrimeField>(
    full_rounds: usize,
    partial_rounds: usize,
    alpha: u64,
    rate: usize,
    capacity: usize,
) -> PoseidonConfig<F> {
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

pub fn poseidon_canonical_config<F: PrimeField>() -> PoseidonConfig<F> {
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;

    poseidon_custom_config(full_rounds, partial_rounds, alpha, rate, 1)
}
