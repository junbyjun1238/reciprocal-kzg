use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::SynthesisError;

pub trait Absorbable {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>);
}

impl Absorbable for usize {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self as u64));
    }
}

impl<T: Absorbable> Absorbable for &T {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self).absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for (T, T) {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0.absorb_into(dest);
        self.1.absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for [T] {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        for t in self.iter() {
            t.absorb_into(dest);
        }
    }
}

impl<T: Absorbable, const N: usize> Absorbable for [T; N] {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_ref().absorb_into(dest);
    }
}

impl<T: Absorbable> Absorbable for Vec<T> {
    fn absorb_into<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_slice().absorb_into(dest);
    }
}

pub trait AbsorbableVar<F: PrimeField> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError>;
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for &T {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        (*self).absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for (T, T) {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.0.absorb_into(dest)?;
        self.1.absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for [T] {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.iter().try_for_each(|t| t.absorb_into(dest))
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>, const N: usize> AbsorbableVar<F> for [T; N] {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.as_ref().absorb_into(dest)
    }
}

impl<F: PrimeField, T: AbsorbableVar<F>> AbsorbableVar<F> for Vec<T> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        self.as_slice().absorb_into(dest)
    }
}
