use super::*;

impl<F: SonobeField, Cfg> LimbedVar<F, Cfg, true> {
    pub fn enforce_lt(&self, other: &Self) -> Result<(), SynthesisError> {
        let delta = other.sub_unaligned(self)?;
        let len = delta.limbs.len();

        if len == 0 {
            return Err(SynthesisError::Unsatisfiable);
        }

        let helper = {
            let cs = delta.limbs.cs();
            let helper = assignment_or_setup(
                cs.clone(),
                || vec![false; len],
                || {
                    let mut helper = vec![false; len];
                    for i in (0..len).rev() {
                        let limb = delta.limbs[i].value()?.into_bigint();
                        if !limb.is_zero() && limb <= F::MODULUS_MINUS_ONE_DIV_TWO {
                            helper[i] = true;
                            break;
                        }
                    }
                    Ok(helper)
                },
            )?;
            Vec::<Boolean<F>>::new_variable_with_inferred_mode(cs, || Ok(helper))?
        };

        let mut p = FpVar::<F>::zero();
        let mut r = FpVar::zero();
        for (b, d) in helper.into_iter().zip(delta.limbs) {
            p += b.select(&d, &FpVar::zero())?;
            r.mul_equals(&d, &FpVar::zero())?;
            r += FpVar::from(b);
        }

        r.enforce_equal(&FpVar::one())?;

        let max_ub = delta.bounds.iter().map(|b| &b.1).max().unwrap();
        if !max_ub.is_positive() {
            return Err(SynthesisError::Unsatisfiable);
        }
        (p - FpVar::one()).enforce_bit_length(max_ub.bits() as usize)?;

        Ok(())
    }
}

impl<F: SonobeField, Cfg, const LHS_ALIGNED: bool> LimbedVar<F, Cfg, LHS_ALIGNED> {
    pub fn add_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<LimbedVar<F, Cfg, false>, SynthesisError> {
        let mut limbs = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bounds::zero(); limbs.len()];
        for (i, v) in self.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&self.bounds[i])
                .checked_for_field::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] += v;
        }
        for (i, v) in other.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&other.bounds[i])
                .checked_for_field::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] += v;
        }
        Ok(LimbedVar::new(limbs, bounds))
    }

    pub fn sub_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<LimbedVar<F, Cfg, false>, SynthesisError> {
        let mut limbs = vec![FpVar::zero(); max(self.limbs.len(), other.limbs.len())];
        let mut bounds = vec![Bounds::zero(); limbs.len()];
        for (i, v) in self.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .add(&self.bounds[i])
                .checked_for_field::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] += v;
        }
        for (i, v) in other.limbs.iter().enumerate() {
            bounds[i] = bounds[i]
                .sub(&other.bounds[i])
                .checked_for_field::<F>()
                .ok_or(SynthesisError::Unsatisfiable)?;
            limbs[i] -= v;
        }
        Ok(LimbedVar::new(limbs, bounds))
    }

    pub fn mul_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<LimbedVar<F, Cfg, false>, SynthesisError> {
        let len = self.limbs.len() + other.limbs.len() - 1;
        if self.limbs.is_constant() || other.limbs.is_constant() {
            return self.mul_constant_unaligned(other, len);
        }
        let (limbs, bounds) = self.allocate_mul_witness(other, len)?;
        self.enforce_mul_relation(other, &limbs, len)?;

        Ok(LimbedVar::new(limbs, bounds))
    }

    fn mul_constant_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
        len: usize,
    ) -> Result<LimbedVar<F, Cfg, false>, SynthesisError> {
        let bounds = (0..len)
            .map(|i| {
                let start = max(i + 1, other.bounds.len()) - other.bounds.len();
                let end = min(i + 1, self.bounds.len());
                Bounds::add_many(
                    &(start..end)
                        .map(|j| self.bounds[j].mul(&other.bounds[i - j]))
                        .collect::<Vec<_>>(),
                )
                .checked_for_field::<F>()
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(SynthesisError::Unsatisfiable)?;

        let limbs = (0..len)
            .map(|i| {
                let start = max(i + 1, other.limbs.len()) - other.limbs.len();
                let end = min(i + 1, self.limbs.len());
                (start..end)
                    .map(|j| &self.limbs[j] * &other.limbs[i - j])
                    .sum()
            })
            .collect();

        Ok(LimbedVar::new(limbs, bounds))
    }

    fn allocate_mul_witness<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
        len: usize,
    ) -> Result<(Vec<FpVar<F>>, Vec<Bounds>), SynthesisError> {
        let cs = self.limbs.cs().or(other.limbs.cs());
        let limbs = assignment_or_setup(
            cs.clone(),
            || vec![F::zero(); len],
            || {
                let mut limbs = vec![F::zero(); len];
                for i in 0..self.limbs.len() {
                    for j in 0..other.limbs.len() {
                        limbs[i + j] += self.limbs[i].value()? * other.limbs[j].value()?;
                    }
                }
                Ok(limbs)
            },
        )?;
        let mut bounds = vec![Bounds::zero(); len];
        for i in 0..self.limbs.len() {
            for j in 0..other.limbs.len() {
                bounds[i + j] = bounds[i + j].add(&self.bounds[i].mul(&other.bounds[j]));
            }
        }

        Ok((
            Vec::new_variable_with_inferred_mode(cs, || Ok(limbs))?,
            bounds
                .into_iter()
                .map(|bound| bound.checked_for_field::<F>())
                .collect::<Option<_>>()
                .ok_or(SynthesisError::Unsatisfiable)?,
        ))
    }

    fn enforce_mul_relation<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
        limbs: &[FpVar<F>],
        len: usize,
    ) -> Result<(), SynthesisError> {
        for c in 1..=len {
            let c = F::from(c as u64);
            let mut t = F::one();
            let mut c_powers = vec![];
            for _ in 0..len {
                c_powers.push(t);
                t *= c;
            }
            let l = self
                .limbs
                .iter()
                .zip(&c_powers)
                .map(|(v, t)| v * *t)
                .sum::<FpVar<_>>();
            let r = other
                .limbs
                .iter()
                .zip(&c_powers)
                .map(|(v, t)| v * *t)
                .sum::<FpVar<_>>();
            let o = limbs
                .iter()
                .zip(&c_powers)
                .map(|(v, t)| v * *t)
                .sum::<FpVar<_>>();
            l.mul_equals(&r, &o)?;
        }

        Ok(())
    }

    pub fn enforce_equal_unaligned<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<F, Cfg, RHS_ALIGNED>,
    ) -> Result<(), SynthesisError> {
        let diff = self.sub_unaligned(other)?;

        let mut carry = FpVar::zero();
        let mut carry_bounds = Bounds::zero();
        let mut group_bounds = Bounds::zero();
        let mut offset = 0;
        let inv = F::from(BigUint::one() << F::BITS_PER_LIMB)
            .inverse()
            .unwrap();

        for (limb, bounds) in diff.limbs.iter().zip(&diff.bounds) {
            if let Some(new_group_bounds) = group_bounds
                .add(&bounds.shl(offset))
                .checked_for_field::<F>()
            {
                carry = (carry + limb) * inv;
                carry_bounds = carry_bounds.add(bounds).shift_right_tight(F::BITS_PER_LIMB);
                group_bounds = new_group_bounds;
                offset += F::BITS_PER_LIMB;
            } else {
                debug_assert!(carry_bounds.shl(offset).0 >= group_bounds.0);
                debug_assert!(carry_bounds.shl(offset).1 <= group_bounds.1);

                (&carry
                    - bigint_to_field_element::<F>(carry_bounds.0.clone())
                        .ok_or(SynthesisError::Unsatisfiable)?)
                .enforce_bit_length(
                    (&carry_bounds.1 - &carry_bounds.0 + BigInt::one()).bits() as usize
                )?;

                carry = (carry + limb) * inv;
                carry_bounds = carry_bounds.add(bounds).shift_right_tight(F::BITS_PER_LIMB);
                group_bounds = carry_bounds.clone();
                offset = 0;
            }
        }

        carry.enforce_equal(&FpVar::zero())?;

        Ok(())
    }
}

impl<Base: SonobeField, Target: SonobeField, const LHS_ALIGNED: bool>
    LimbedVar<Base, Target, LHS_ALIGNED>
{
    pub fn modulo(&self) -> Result<LimbedVar<Base, Target, true>, SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, Target::MODULUS.into());
        let (q, r) = self.allocate_modulo_witness(cs, &m)?;
        self.enforce_modulo_relation(&q, &r, m)?;

        Ok(r)
    }

    fn allocate_modulo_witness(
        &self,
        cs: ConstraintSystemRef<Base>,
        m: &BigInt,
    ) -> Result<(LimbedVar<Base, Target, true>, LimbedVar<Base, Target, true>), SynthesisError>
    {
        let (q_value, r_value) = assignment_or_setup(
            cs.clone(),
            || (BigInt::zero(), BigInt::zero()),
            || {
                let v = compose(self.limbs.value()?);
                let q = v.div_floor(m);
                let r = v - &q * m;
                Ok((q, r))
            },
        )?;

        Ok((
            LimbedVar::new_variable_with_inferred_mode(cs.clone(), || {
                Ok((
                    q_value,
                    Bounds(self.lbound().div_floor(m), self.ubound().div_floor(m)),
                ))
            })?,
            LimbedVar::new_variable_with_inferred_mode(cs, || {
                Ok((r_value, Bounds(Zero::zero(), m.clone())))
            })?,
        ))
    }

    fn enforce_modulo_relation(
        &self,
        q: &LimbedVar<Base, Target, true>,
        r: &LimbedVar<Base, Target, true>,
        m: BigInt,
    ) -> Result<(), SynthesisError> {
        let m = LimbedVar::constant(m);
        q.mul_unaligned(&m)?
            .add_unaligned(r)?
            .enforce_equal_unaligned(self)?;
        r.enforce_lt(&m)?;
        Ok(())
    }

    pub fn enforce_congruent<const RHS_ALIGNED: bool>(
        &self,
        other: &LimbedVar<Base, Target, RHS_ALIGNED>,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs();
        let m = BigInt::from_biguint(Sign::Plus, Target::MODULUS.into());
        let q = LimbedVar::new_variable_with_inferred_mode(cs.clone(), || {
            let quotient = assignment_or_setup(cs.clone(), BigInt::zero, || {
                let x = compose(self.limbs.value()?);
                let y = compose(other.limbs.value()?);
                Ok((x - y).div_floor(&m))
            })?;
            Ok((
                quotient,
                Bounds(self.lbound().div_floor(&m), self.ubound().div_floor(&m)),
            ))
        })?;

        let m = LimbedVar::constant(m);

        self.sub_unaligned(other)?
            .enforce_equal_unaligned(&q.mul_unaligned(&m)?)
    }
}
