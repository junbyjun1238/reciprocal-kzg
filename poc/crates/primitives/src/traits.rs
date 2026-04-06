pub use crate::algebra::{
    field::SonobeField,
    group::{CF1, CF2, SonobeCurve},
};

pub trait Dummy<Cfg> {
    fn dummy(cfg: Cfg) -> Self;
}

impl<T: Default + Clone> Dummy<usize> for Vec<T> {
    fn dummy(cfg: usize) -> Self {
        vec![Default::default(); cfg]
    }
}

impl<Cfg, T: Dummy<Cfg> + Copy, const N: usize> Dummy<Cfg> for [T; N] {
    fn dummy(cfg: Cfg) -> Self {
        [T::dummy(cfg); N]
    }
}

impl<Cfg: Copy, A: Dummy<Cfg>, B: Dummy<Cfg>> Dummy<Cfg> for (A, B) {
    fn dummy(cfg: Cfg) -> Self {
        (A::dummy(cfg), B::dummy(cfg))
    }
}

pub trait ToPublicInputs<F> {
    fn to_public_inputs(&self) -> Vec<F>;
}

impl<F, T: ToPublicInputs<F>> ToPublicInputs<F> for [T] {
    fn to_public_inputs(&self) -> Vec<F> {
        self.iter()
            .flat_map(ToPublicInputs::<F>::to_public_inputs)
            .collect()
    }
}

pub trait ToEmulatedPublicInputs<F> {
    fn to_emulated_public_inputs(&self) -> Vec<F>;
}

impl<F, T: ToEmulatedPublicInputs<F>> ToEmulatedPublicInputs<F> for [T] {
    fn to_emulated_public_inputs(&self) -> Vec<F> {
        self.iter()
            .flat_map(ToEmulatedPublicInputs::<F>::to_emulated_public_inputs)
            .collect()
    }
}
