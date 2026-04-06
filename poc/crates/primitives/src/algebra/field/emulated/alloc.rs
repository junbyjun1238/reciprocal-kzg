use super::*;

pub(super) fn compute_bounds(lb: &BigInt, ub: &BigInt, bits_per_limb: usize) -> Vec<Bounds> {
    let len = max(lb.bits(), ub.bits()) as usize;
    let (n_full_limbs, n_remaining_bits) = len.div_rem(&bits_per_limb);

    let mut bounds = vec![
        Bounds(
            if lb.is_negative() {
                BigInt::one() - (BigInt::one() << bits_per_limb)
            } else {
                BigInt::zero()
            },
            if ub.is_positive() {
                (BigInt::one() << bits_per_limb) - BigInt::one()
            } else {
                BigInt::zero()
            },
        );
        n_full_limbs
    ];

    if !n_remaining_bits.is_zero() {
        let d = BigInt::one() << (len - n_remaining_bits);
        bounds.push(Bounds(lb.div_floor(&d), ub.div_ceil(&d)));
    }

    bounds
}

impl<F: SonobeField, Cfg> AllocVar<(BigInt, Bounds), F> for LimbedVar<F, Cfg, true> {
    fn new_variable<T: Borrow<(BigInt, Bounds)>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let (x, Bounds(lb, ub)) = v.borrow();

        if x < lb || x > ub {
            return Err(SynthesisError::Unsatisfiable);
        }

        let len = max(lb.bits(), ub.bits()) as usize;

        let x_is_neg = x.is_negative();
        let mut x_bits = x
            .magnitude()
            .to_radix_le(2)
            .into_iter()
            .map(|i| i == 1)
            .collect::<Vec<_>>();
        x_bits.resize(len, false);

        let x_is_neg = if !lb.is_negative() {
            Boolean::FALSE
        } else if !ub.is_positive() {
            Boolean::TRUE
        } else {
            Boolean::new_variable(cs.clone(), || Ok(x_is_neg), mode)?
        };
        let x_bits = Vec::new_variable(cs, || Ok(x_bits), mode)?;

        let limbs = x_bits
            .chunks(F::BITS_PER_LIMB)
            .map(|chunk| {
                let limb_abs = Boolean::le_bits_to_fp(chunk)?;
                x_is_neg.select(&limb_abs.negate()?, &limb_abs)
            })
            .collect::<Result<_, _>>()?;

        let bounds = compute_bounds(lb, ub, F::BITS_PER_LIMB);

        let var = Self::new(limbs, bounds);

        #[allow(clippy::if_same_then_else)]
        if lb.is_zero() && ub + BigInt::one() == BigInt::one() << len {
        } else if BigInt::one() - lb == BigInt::one() << len && ub.is_zero() {
        } else if BigInt::one() - lb == BigInt::one() << len
            && ub + BigInt::one() == BigInt::one() << len
        {
        } else {
            var.enforce_lt(&Self::constant(ub + BigInt::one()))?;
            Self::constant(lb - BigInt::one()).enforce_lt(&var)?;
        }

        Ok(var)
    }

    fn new_constant(
        _cs: impl Into<Namespace<F>>,
        t: impl Borrow<(BigInt, Bounds)>,
    ) -> Result<Self, SynthesisError> {
        let (x, Bounds(lb, ub)) = t.borrow();

        if x < lb || x > ub {
            return Err(SynthesisError::Unsatisfiable);
        }

        let bits = x
            .magnitude()
            .to_radix_le(2)
            .into_iter()
            .map(|i| i == 1)
            .collect::<Vec<_>>();

        let (limbs, bounds) = bits
            .chunks(F::BITS_PER_LIMB)
            .map(F::BigInt::from_bits_le)
            .map(|v| {
                let v_field = if x.is_negative() {
                    -F::from(v)
                } else {
                    F::from(v)
                };
                let v_bigint = BigInt::from_biguint(x.sign(), v.into());
                (FpVar::constant(v_field), Bounds(v_bigint.clone(), v_bigint))
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();

        Ok(Self::new(limbs, bounds))
    }
}

impl<F: SonobeField, G: SonobeField, Cfg> AllocVar<G, F> for LimbedVar<F, Cfg, true> {
    fn new_variable<T: Borrow<G>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Self::new_variable(
            cs,
            || {
                f().map(|v| {
                    (
                        BigInt::from_biguint(Sign::Plus, (*v.borrow()).into()),
                        Bounds(Zero::zero(), G::MODULUS.into().into()),
                    )
                })
            },
            mode,
        )
    }
}

impl<F: SonobeField, Cfg> LimbedVar<F, Cfg, true> {
    pub fn constant(x: BigInt) -> Self {
        Self::new_constant(ConstraintSystemRef::None, (x.clone(), Bounds(x.clone(), x))).unwrap()
    }
}
