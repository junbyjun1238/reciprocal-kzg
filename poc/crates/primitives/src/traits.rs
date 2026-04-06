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

pub trait Inputize<F> {
    fn inputize(&self) -> Vec<F>;
}

impl<F, T: Inputize<F>> Inputize<F> for [T] {
    fn inputize(&self) -> Vec<F> {
        self.iter().flat_map(Inputize::<F>::inputize).collect()
    }
}

pub trait InputizeEmulated<F> {
    fn inputize_emulated(&self) -> Vec<F>;
}

impl<F, T: InputizeEmulated<F>> InputizeEmulated<F> for [T] {
    fn inputize_emulated(&self) -> Vec<F> {
        self.iter()
            .flat_map(InputizeEmulated::<F>::inputize_emulated)
            .collect()
    }
}
