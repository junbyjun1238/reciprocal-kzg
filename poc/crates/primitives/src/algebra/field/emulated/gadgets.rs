use super::alloc::compute_bounds;
use super::*;

impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, true>>
    for LimbedVar<Base, Target, true>
{
    fn enforce_equivalent(&self, other: &Self) -> Result<(), SynthesisError> {
        self.enforce_equal(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, true>>
    for LimbedVar<Base, Target, false>
{
    fn enforce_equivalent(
        &self,
        other: &LimbedVar<Base, Target, true>,
    ) -> Result<(), SynthesisError> {
        self.enforce_congruent(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, false>>
    for LimbedVar<Base, Target, true>
{
    fn enforce_equivalent(
        &self,
        other: &LimbedVar<Base, Target, false>,
    ) -> Result<(), SynthesisError> {
        self.enforce_congruent(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> EquivalenceGadget<LimbedVar<Base, Target, false>>
    for LimbedVar<Base, Target, false>
{
    fn enforce_equivalent(
        &self,
        other: &LimbedVar<Base, Target, false>,
    ) -> Result<(), SynthesisError> {
        self.enforce_congruent(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), true>> for LimbedVar<F, (), true> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), true>) -> Result<(), SynthesisError> {
        self.enforce_equal(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), true>> for LimbedVar<F, (), false> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), true>) -> Result<(), SynthesisError> {
        self.enforce_equal_unaligned(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), false>> for LimbedVar<F, (), true> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), false>) -> Result<(), SynthesisError> {
        self.enforce_equal_unaligned(other)
    }
}

impl<F: SonobeField> EquivalenceGadget<LimbedVar<F, (), false>> for LimbedVar<F, (), false> {
    fn enforce_equivalent(&self, other: &LimbedVar<F, (), false>) -> Result<(), SynthesisError> {
        self.enforce_equal_unaligned(other)
    }
}

impl<Base: SonobeField, Target: SonobeField> TryFrom<LimbedVar<Base, Target, false>>
    for LimbedVar<Base, Target, true>
{
    type Error = SynthesisError;

    fn try_from(v: LimbedVar<Base, Target, false>) -> Result<Self, Self::Error> {
        v.modulo()
    }
}

impl<Base: SonobeField, Target: SonobeField> TwoStageFieldVar for LimbedVar<Base, Target, true> {
    type Intermediate = LimbedVar<Base, Target, false>;
}

impl<F: SonobeField, Cfg> EqGadget<F> for LimbedVar<F, Cfg, true> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        let mut result = Boolean::TRUE;
        if self.limbs.len() != other.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self.bounds.len() != other.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..self.limbs.len() {
            if self.bounds[i] != other.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            result &= self.limbs[i].is_eq(&other.limbs[i])?;
        }
        Ok(result)
    }

    fn enforce_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        if self.limbs.len() != other.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self.bounds.len() != other.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..self.limbs.len() {
            if self.bounds[i] != other.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            self.limbs[i].enforce_equal(&other.limbs[i])?;
        }
        Ok(())
    }

    fn enforce_not_equal(&self, other: &Self) -> Result<(), SynthesisError> {
        if self.limbs.len() != other.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self.bounds.len() != other.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..self.limbs.len() {
            if self.bounds[i] != other.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            self.limbs[i].enforce_not_equal(&other.limbs[i])?;
        }
        Ok(())
    }

    fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        if should_enforce.is_constant() {
            if should_enforce.value()? {
                return self.enforce_equal(other);
            } else {
                return self.enforce_not_equal(other);
            }
        }
        self.is_eq(other)?
            .conditional_enforce_equal(&Boolean::TRUE, should_enforce)
    }
}

impl<F: SonobeField, Cfg> FromBitsGadget<F> for LimbedVar<F, Cfg, true> {
    fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self, SynthesisError> {
        Self::from_bounded_bits_le(
            bits,
            Bounds(
                BigInt::zero(),
                (BigInt::one() << bits.len()) - BigInt::one(),
            ),
        )
    }

    fn from_bounded_bits_le(bits: &[Boolean<F>], bounds: Bounds) -> Result<Self, SynthesisError> {
        Ok(Self::new(
            bits.chunks(F::BITS_PER_LIMB)
                .map(Boolean::le_bits_to_fp)
                .collect::<Result<_, _>>()?,
            compute_bounds(&bounds.0, &bounds.1, F::BITS_PER_LIMB),
        ))
    }
}

impl<F: PrimeField, Cfg: Clone> CondSelectGadget<F> for LimbedVar<F, Cfg, true> {
    fn conditionally_select(
        cond: &Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        if true_value.limbs.len() != false_value.limbs.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if true_value.bounds.len() != false_value.bounds.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut limbs = vec![];
        let mut bounds = vec![];
        for i in 0..true_value.limbs.len() {
            if true_value.bounds[i] != false_value.bounds[i] {
                return Err(SynthesisError::Unsatisfiable);
            }
            limbs.push(cond.select(&true_value.limbs[i], &false_value.limbs[i])?);
            bounds.push(true_value.bounds[i].clone());
        }
        Ok(Self {
            _cfg: PhantomData,
            limbs,
            bounds,
        })
    }
}

impl<F: PrimeField, Cfg> ToBitsGadget<F> for LimbedVar<F, Cfg, true> {
    fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        for bound in &self.bounds {
            if bound.0 < BigInt::zero() {
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        Ok(self
            .limbs
            .iter()
            .zip(&self.bounds)
            .map(|(limb, bound)| limb.to_n_bits_le(bound.1.bits() as usize))
            .collect::<Result<Vec<_>, _>>()?
            .concat())
    }
}

impl<F: PrimeField, Cfg> AbsorbableVar<F> for LimbedVar<F, Cfg, true> {
    fn absorb_into(&self, dest: &mut Vec<FpVar<F>>) -> Result<(), SynthesisError> {
        let bits_per_limb = F::MODULUS_BIT_SIZE as usize - 1;

        self.to_bits_le()?
            .chunks(bits_per_limb)
            .try_for_each(|i| Boolean::le_bits_to_fp(i).map(|v| dest.push(v)))
    }
}

impl<CF: SonobeField, Cfg> MatrixGadget<LimbedVar<CF, Cfg, false>>
    for SparseMatrixVar<LimbedVar<CF, Cfg, false>>
{
    fn mul_vector(
        &self,
        v: &impl Index<usize, Output = LimbedVar<CF, Cfg, false>>,
    ) -> Result<Vec<LimbedVar<CF, Cfg, false>>, SynthesisError> {
        self.0
            .iter()
            .map(|row| {
                let len = row
                    .iter()
                    .map(|(value, col_i)| value.limbs.len() + v[*col_i].limbs.len() - 1)
                    .max()
                    .unwrap_or(0);
                let bounds = (0..len)
                    .map(|i| {
                        Bounds::add_many(
                            &row.iter()
                                .flat_map(|(value, col_i)| {
                                    let start =
                                        max(i + 1, v[*col_i].bounds.len()) - v[*col_i].bounds.len();
                                    let end = min(i + 1, value.bounds.len());
                                    (start..end)
                                        .map(|j| value.bounds[j].mul(&v[*col_i].bounds[i - j]))
                                })
                                .collect::<Vec<_>>(),
                        )
                        .checked_for_field::<CF>()
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or(SynthesisError::Unsatisfiable)?;
                let limbs = (0..len)
                    .map(|i| {
                        row.iter()
                            .flat_map(|(value, col_i)| {
                                let start =
                                    max(i + 1, v[*col_i].limbs.len()) - v[*col_i].limbs.len();
                                let end = min(i + 1, value.limbs.len());
                                (start..end).map(|j| &value.limbs[j] * &v[*col_i].limbs[i - j])
                            })
                            .sum()
                    })
                    .collect();
                Ok(LimbedVar::new(limbs, bounds))
            })
            .collect()
    }
}
