use ark_ff::Field;
use ark_pallas::{Fq, Fr};
use ark_relations::gr1cs::ConstraintSystem;
use ark_std::{
    UniformRand,
    error::Error,
    rand::{Rng, thread_rng},
};
use num_bigint::RandBigInt;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use super::*;

#[test]
fn test_eq() -> Result<(), Box<dyn Error>> {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let zero = LimbedVar::<Fr, (), true>::new(vec![], vec![]);
    let zero2 = LimbedVar::<Fr, (), true>::new(
        vec![
            FpVar::new_witness(cs.clone(), || {
                Ok(Fr::from(BigUint::one() << Fr::BITS_PER_LIMB))
            })?,
            FpVar::new_witness(cs.clone(), || Ok(-Fr::one()))?,
        ],
        vec![
            Bounds(
                -(BigInt::one() << (Fr::BITS_PER_LIMB * 2)),
                BigInt::one() << (Fr::BITS_PER_LIMB * 2),
            ),
            Bounds(
                -(BigInt::one() << (Fr::BITS_PER_LIMB * 2)),
                BigInt::one() << (Fr::BITS_PER_LIMB * 2),
            ),
        ],
    );
    let zero3 = LimbedVar::<Fr, (), true>::new(
        vec![
            FpVar::new_witness(cs.clone(), || {
                Ok(Fr::from(BigUint::one() << Fr::BITS_PER_LIMB))
            })?,
            FpVar::new_witness(cs.clone(), || Ok(-Fr::one()))?,
        ],
        vec![
            Bounds(
                BigInt::zero(),
                BigInt::from_biguint(Sign::Plus, Fr::MODULUS_MINUS_ONE_DIV_TWO.into()),
            ),
            Bounds(
                -BigInt::from_biguint(Sign::Plus, Fr::MODULUS_MINUS_ONE_DIV_TWO.into()),
                BigInt::zero(),
            ),
        ],
    );

    zero.enforce_equal_unaligned(&zero2)?;
    zero.enforce_equal_unaligned(&zero3)?;

    let rng = &mut thread_rng();
    let n_limbs = 100;

    let coeffs = (0..n_limbs)
        .map(|_| if rng.gen_bool(0.5) { -Fr::one() } else { Fr::one() }
            * Fr::from(rng.gen_biguint(Fr::BITS_PER_LIMB as u64 * 2 - 1)))
        .collect::<Vec<_>>();
    let unaligned = LimbedVar::<Fr, (), true>::new(
        Vec::new_witness(cs.clone(), || Ok(&coeffs[..]))?,
        vec![
            Bounds(
                -(BigInt::one() << (Fr::BITS_PER_LIMB * 2)),
                BigInt::one() << (Fr::BITS_PER_LIMB * 2),
            );
            n_limbs
        ],
    );

    let aligned = EmulatedIntVar::new_witness(cs.clone(), || {
        let v = compose(&coeffs[..]);
        Ok((
            v,
            Bounds(
                BigInt::one() - (BigInt::one() << (Fr::BITS_PER_LIMB * 2 * n_limbs)),
                (BigInt::one() << (Fr::BITS_PER_LIMB * 2 * n_limbs)) - BigInt::one(),
            ),
        ))
    })?;
    aligned.enforce_equal_unaligned(&unaligned)?;

    assert!(cs.is_satisfied()?);

    let mut unaligned_incorrect = unaligned.clone();
    unaligned_incorrect.limbs[0] = if coeffs[0].is_zero() {
        FpVar::new_witness(cs.clone(), || Ok(Fr::one()))?
    } else {
        FpVar::new_witness(cs.clone(), || Ok(-coeffs[0]))?
    };
    aligned.enforce_equal_unaligned(&unaligned_incorrect)?;

    assert!(!cs.is_satisfied()?);

    Ok(())
}

#[test]
fn test_alloc() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();

    let size = 1024;
    let mut lbs = vec![BigInt::zero()];
    let mut ubs: Vec<BigInt> = vec![(BigInt::one() << size) - BigInt::one()];
    lbs.push(-ubs[0].clone());
    ubs.push(BigInt::zero());
    lbs.push(-ubs[0].clone());
    ubs.push(ubs[0].clone());
    lbs.push(rng.gen_bigint_range(&-&ubs[0], &BigInt::zero()));
    ubs.push(BigInt::zero());
    lbs.push(BigInt::zero());
    ubs.push(rng.gen_bigint_range(&BigInt::zero(), &ubs[0]));
    lbs.push(rng.gen_bigint_range(&-&ubs[0], &BigInt::zero()));
    ubs.push(rng.gen_bigint_range(&BigInt::zero(), &ubs[0]));
    lbs.push(rng.gen_bigint_range(&-&ubs[0], &BigInt::zero()));
    ubs.push(rng.gen_bigint_range(lbs.last().unwrap(), &BigInt::zero()));
    lbs.push(rng.gen_bigint_range(&BigInt::zero(), &ubs[0]));
    ubs.push(rng.gen_bigint_range(lbs.last().unwrap(), &ubs[0]));

    for (lb, ub) in lbs.into_iter().zip(ubs.into_iter()) {
        let mut v = vec![
            lb.clone(),
            ub.clone(),
            &lb + BigInt::one(),
            &ub - BigInt::one(),
        ];
        if BigInt::zero() >= lb && BigInt::zero() <= ub {
            v.push(BigInt::zero());
        }
        for _ in 0..10 {
            v.push(rng.gen_bigint_range(&lb, &ub));
        }
        for a in v {
            let cs = ConstraintSystem::<Fr>::new_ref();

            let a_var = EmulatedIntVar::new_witness(cs.clone(), || {
                Ok((a.clone(), Bounds(lb.clone(), ub.clone())))
            })?;

            let a_const = EmulatedIntVar::<Fr>::constant(a.clone());

            assert_eq!(a, a_var.value()?);
            assert_eq!(a, a_const.value()?);
            assert!(cs.is_satisfied()?);
        }
    }

    Ok(())
}

#[test]
fn test_mul_bigint() -> Result<(), Box<dyn Error>> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let size = 2048;

    let rng = &mut thread_rng();
    let a = rng.gen_bigint(size as u64);
    let b = rng.gen_bigint(size as u64);
    let ab = &a * &b;
    let aab = &a * &ab;
    let abb = &ab * &b;

    let a_var = EmulatedIntVar::new_witness(cs.clone(), || {
        Ok((
            a,
            Bounds(
                BigInt::one() - (BigInt::one() << size),
                (BigInt::one() << size) - BigInt::one(),
            ),
        ))
    })?;
    let b_var = EmulatedIntVar::new_witness(cs.clone(), || {
        Ok((
            b,
            Bounds(
                BigInt::one() - (BigInt::one() << size),
                (BigInt::one() << size) - BigInt::one(),
            ),
        ))
    })?;
    let ab_var = EmulatedIntVar::new_witness(cs.clone(), || {
        Ok((
            ab,
            Bounds(
                BigInt::one() - (BigInt::one() << (size * 2)),
                (BigInt::one() << (size * 2)) - BigInt::one(),
            ),
        ))
    })?;
    let aab_var = EmulatedIntVar::new_witness(cs.clone(), || {
        Ok((
            aab,
            Bounds(
                BigInt::one() - (BigInt::one() << (size * 3)),
                (BigInt::one() << (size * 3)) - BigInt::one(),
            ),
        ))
    })?;
    let abb_var = EmulatedIntVar::new_witness(cs.clone(), || {
        Ok((
            abb,
            Bounds(
                BigInt::one() - (BigInt::one() << (size * 3)),
                (BigInt::one() << (size * 3)) - BigInt::one(),
            ),
        ))
    })?;

    let neg_a_var = EmulatedFieldVar::constant(BigInt::zero()) - &a_var;
    let neg_b_var = EmulatedFieldVar::constant(BigInt::zero()) - &b_var;
    let neg_ab_var = EmulatedFieldVar::constant(BigInt::zero()) - &ab_var;
    let neg_aab_var = EmulatedFieldVar::constant(BigInt::zero()) - &aab_var;
    let neg_abb_var = EmulatedFieldVar::constant(BigInt::zero()) - &abb_var;

    a_var
        .mul_unaligned(&b_var)?
        .enforce_equal_unaligned(&ab_var)?;
    neg_a_var
        .mul_unaligned(&neg_b_var)?
        .enforce_equal_unaligned(&ab_var)?;
    a_var
        .mul_unaligned(&neg_b_var)?
        .enforce_equal_unaligned(&neg_ab_var)?;
    neg_a_var
        .mul_unaligned(&b_var)?
        .enforce_equal_unaligned(&neg_ab_var)?;

    a_var
        .mul_unaligned(&ab_var)?
        .enforce_equal_unaligned(&aab_var)?;
    neg_a_var
        .mul_unaligned(&neg_ab_var)?
        .enforce_equal_unaligned(&aab_var)?;
    a_var
        .mul_unaligned(&neg_ab_var)?
        .enforce_equal_unaligned(&neg_aab_var)?;
    neg_a_var
        .mul_unaligned(&ab_var)?
        .enforce_equal_unaligned(&neg_aab_var)?;

    ab_var
        .mul_unaligned(&b_var)?
        .enforce_equal_unaligned(&abb_var)?;
    neg_ab_var
        .mul_unaligned(&neg_b_var)?
        .enforce_equal_unaligned(&abb_var)?;
    ab_var
        .mul_unaligned(&neg_b_var)?
        .enforce_equal_unaligned(&neg_abb_var)?;
    neg_ab_var
        .mul_unaligned(&b_var)?
        .enforce_equal_unaligned(&neg_abb_var)?;

    assert!(cs.is_satisfied()?);
    Ok(())
}

#[test]
fn test_mul_fq() -> Result<(), Box<dyn Error>> {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let rng = &mut thread_rng();
    let a = Fq::rand(rng);
    let b = Fq::rand(rng);
    let ab = a * b;
    let aab = a * ab;
    let abb = ab * b;

    let a_var = EmulatedFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(a))?;
    let b_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(b))?;
    let ab_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(ab))?;
    let aab_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(aab))?;
    let abb_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(abb))?;

    let neg_a_var = EmulatedFieldVar::constant(BigInt::zero()) - &a_var;
    let neg_b_var = EmulatedFieldVar::constant(BigInt::zero()) - &b_var;
    let neg_ab_var = EmulatedFieldVar::constant(BigInt::zero()) - &ab_var;
    let neg_aab_var = EmulatedFieldVar::constant(BigInt::zero()) - &aab_var;
    let neg_abb_var = EmulatedFieldVar::constant(BigInt::zero()) - &abb_var;

    a_var.mul_unaligned(&b_var)?.enforce_congruent(&ab_var)?;
    neg_a_var
        .mul_unaligned(&neg_b_var)?
        .enforce_congruent(&ab_var)?;
    a_var
        .mul_unaligned(&neg_b_var)?
        .enforce_congruent(&neg_ab_var)?;
    neg_a_var
        .mul_unaligned(&b_var)?
        .enforce_congruent(&neg_ab_var)?;

    a_var.mul_unaligned(&ab_var)?.enforce_congruent(&aab_var)?;
    neg_a_var
        .mul_unaligned(&neg_ab_var)?
        .enforce_congruent(&aab_var)?;
    a_var
        .mul_unaligned(&neg_ab_var)?
        .enforce_congruent(&neg_aab_var)?;
    neg_a_var
        .mul_unaligned(&ab_var)?
        .enforce_congruent(&neg_aab_var)?;

    ab_var.mul_unaligned(&b_var)?.enforce_congruent(&abb_var)?;
    neg_ab_var
        .mul_unaligned(&neg_b_var)?
        .enforce_congruent(&abb_var)?;
    ab_var
        .mul_unaligned(&neg_b_var)?
        .enforce_congruent(&neg_abb_var)?;
    neg_ab_var
        .mul_unaligned(&b_var)?
        .enforce_congruent(&neg_abb_var)?;

    assert_eq!(a_var.mul_unaligned(&b_var)?.modulo()?.value()?, ab);
    assert_eq!(neg_a_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?, ab);
    assert_eq!(a_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?, -ab);
    assert_eq!(neg_a_var.mul_unaligned(&b_var)?.modulo()?.value()?, -ab);

    assert_eq!(a_var.mul_unaligned(&ab_var)?.modulo()?.value()?, aab);
    assert_eq!(
        neg_a_var.mul_unaligned(&neg_ab_var)?.modulo()?.value()?,
        aab
    );
    assert_eq!(a_var.mul_unaligned(&neg_ab_var)?.modulo()?.value()?, -aab);
    assert_eq!(neg_a_var.mul_unaligned(&ab_var)?.modulo()?.value()?, -aab);

    assert_eq!(ab_var.mul_unaligned(&b_var)?.modulo()?.value()?, abb);
    assert_eq!(
        neg_ab_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?,
        abb
    );
    assert_eq!(ab_var.mul_unaligned(&neg_b_var)?.modulo()?.value()?, -abb);
    assert_eq!(neg_ab_var.mul_unaligned(&b_var)?.modulo()?.value()?, -abb);

    assert!(cs.is_satisfied()?);
    Ok(())
}

#[test]
fn test_pow() -> Result<(), Box<dyn Error>> {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let rng = &mut thread_rng();
    let a = Fq::rand(rng);

    let a_var = EmulatedFieldVar::<Fr, Fq>::new_witness(cs.clone(), || Ok(a))?;

    let mut r_var = a_var.clone();
    for _ in 0..16 {
        r_var = r_var.mul_unaligned(&r_var)?.modulo()?;
    }
    r_var = r_var.mul_unaligned(&a_var)?.modulo()?;
    assert_eq!(a.pow([65537u64]), r_var.value()?);
    assert!(cs.is_satisfied()?);
    Ok(())
}

#[test]
fn test_vector_dot_product_constraints() -> Result<(), Box<dyn Error>> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let len = 1000;

    let rng = &mut thread_rng();
    let a = (0..len).map(|_| Fq::rand(rng)).collect::<Vec<Fq>>();
    let b = (0..len).map(|_| Fq::rand(rng)).collect::<Vec<Fq>>();
    let c = a.iter().zip(b.iter()).map(|(a, b)| a * b).sum::<Fq>();

    let a_var = Vec::<EmulatedFieldVar<Fr, Fq>>::new_witness(cs.clone(), || Ok(a))?;
    let b_var = Vec::<EmulatedFieldVar<Fr, Fq>>::new_witness(cs.clone(), || Ok(b))?;
    let c_var = EmulatedFieldVar::new_witness(cs.clone(), || Ok(c))?;

    let mut r_var: LimbedVar<Fr, Fq, false> =
        EmulatedFieldVar::constant(BigUint::zero().into()).into();
    for (a, b) in a_var.into_iter().zip(b_var.into_iter()) {
        r_var = r_var.add_unaligned(&a.mul_unaligned(&b)?)?;
    }
    r_var.enforce_congruent(&c_var)?;

    assert!(cs.is_satisfied()?);
    Ok(())
}
