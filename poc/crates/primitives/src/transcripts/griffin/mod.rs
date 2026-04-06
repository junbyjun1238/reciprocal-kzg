// Copyright (c) 2021 Graz University of Technology
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use ark_ff::{LegendreSymbol, PrimeField, field_hashers::hash_to_field};
use ark_r1cs_std::{
    GR1CSVar,
    alloc::AllocVar,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::utils::assignments::assignment_or_setup;

pub mod sponge;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct GriffinParams<F: PrimeField> {
    round_constants: Vec<Vec<F>>,
    t: usize,
    d: usize,
    d_inv: Vec<bool>,
    rounds: usize,
    alpha_beta: Vec<[F; 2]>,
    mat: Vec<Vec<F>>,
    rate: usize,
    capacity: usize,
}

impl<F: PrimeField> GriffinParams<F> {
    const INIT_SHAKE: &'static str = "Griffin";

    pub fn new(t: usize, d: usize, rounds: usize) -> Self {
        // Equivalent to `assert!(t == 3 || t % 4 == 0);`, but bypass clippy's
        // warning about `is_multiple_of`.
        assert!(t == 3 || t & 3 == 0);
        assert!(d == 3 || d == 5);
        assert!(rounds >= 1);

        let mut shake = Self::init_shake();

        let d_inv = BigUint::from(d)
            .modinv(&(-F::one()).into())
            .unwrap()
            .to_radix_be(2)
            .into_iter()
            .map(|i| i != 0)
            .skip_while(|i| !i)
            .collect();
        let round_constants = Self::instantiate_round_constants(t, rounds, &mut shake);
        let alpha_beta = Self::instantiate_alpha_beta(t, &mut shake);

        let mat = Self::instantiate_matrix(t);

        GriffinParams {
            round_constants,
            t,
            d,
            d_inv,
            rounds,
            alpha_beta,
            mat,
            rate: t - 1,
            capacity: 1,
        }
    }

    fn init_shake() -> Shake128Reader {
        let mut shake = Shake128::default();
        shake.update(Self::INIT_SHAKE.as_bytes());
        for i in F::characteristic() {
            shake.update(&i.to_le_bytes());
        }
        shake.finalize_xof()
    }

    fn instantiate_round_constants(
        t: usize,
        rounds: usize,
        shake: &mut Shake128Reader,
    ) -> Vec<Vec<F>> {
        (0..rounds - 1)
            .map(|_| (0..t).map(|_| hash_to_field::<_, _, 128>(shake)).collect())
            .collect()
    }

    fn instantiate_alpha_beta(t: usize, shake: &mut Shake128Reader) -> Vec<[F; 2]> {
        fn hash_to_non_zero_field<F: PrimeField>(reader: &mut impl XofReader) -> F {
            loop {
                let element = hash_to_field::<F, _, 128>(reader);
                if !element.is_zero() {
                    return element;
                }
            }
        }

        let mut alpha_beta = Vec::with_capacity(t - 2);

        loop {
            let alpha = hash_to_non_zero_field::<F>(shake);
            let mut beta = hash_to_non_zero_field::<F>(shake);
            while alpha == beta {
                beta = hash_to_non_zero_field::<F>(shake);
            }
            let mut symbol = alpha;
            symbol.square_in_place();
            let mut tmp = beta;
            tmp.double_in_place();
            tmp.double_in_place();
            symbol.sub_assign(&tmp);
            if symbol.legendre() == LegendreSymbol::QuadraticNonResidue {
                alpha_beta.push([alpha, beta]);
                break;
            }
        }

        for i in 2..t - 1 {
            let mut alpha = alpha_beta[0][0];
            let mut beta = alpha_beta[0][1];
            alpha.mul_assign(&F::from(i as u64));
            beta.mul_assign(&F::from((i * i) as u64));
            while alpha == beta {
                beta = hash_to_non_zero_field::<F>(shake);
            }

            #[cfg(debug_assertions)]
            {
                let mut symbol = alpha;
                symbol.square_in_place();
                let mut tmp = beta;
                tmp.double_in_place();
                tmp.double_in_place();
                symbol.sub_assign(&tmp);
                assert_eq!(symbol.legendre(), LegendreSymbol::QuadraticNonResidue);
            }

            alpha_beta.push([alpha, beta]);
        }

        alpha_beta
    }

    fn instantiate_matrix(t: usize) -> Vec<Vec<F>> {
        if t == 3 {
            let row = vec![F::from(2), F::from(1), F::from(1)];
            let t = row.len();
            let mut mat: Vec<Vec<F>> = Vec::with_capacity(t);
            let mut rot = row.to_owned();
            mat.push(rot.clone());
            for _ in 1..t {
                rot.rotate_right(1);
                mat.push(rot.clone());
            }
            mat
        } else {
            let row1 = vec![F::from(5), F::from(7), F::from(1), F::from(3)];
            let row2 = vec![F::from(4), F::from(6), F::from(1), F::from(1)];
            let row3 = vec![F::from(1), F::from(3), F::from(5), F::from(7)];
            let row4 = vec![F::from(1), F::from(1), F::from(4), F::from(6)];
            let c_mat = vec![row1, row2, row3, row4];
            if t == 4 {
                c_mat
            } else {
                assert_eq!(t % 4, 0);
                let mut mat: Vec<Vec<F>> = vec![vec![F::zero(); t]; t];
                for (row, matrow) in mat.iter_mut().enumerate().take(t) {
                    for (col, matitem) in matrow.iter_mut().enumerate().take(t) {
                        let row_mod = row % 4;
                        let col_mod = col % 4;
                        *matitem = c_mat[row_mod][col_mod];
                        if row / 4 == col / 4 {
                            matitem.add_assign(&c_mat[row_mod][col_mod]);
                        }
                    }
                }
                mat
            }
        }
    }
}

pub struct Griffin;

impl Griffin {
    fn affine_3<F: PrimeField>(params: &GriffinParams<F>, input: &mut [F], round: usize) {
        let mut sum = input[0];
        input.iter().skip(1).for_each(|el| sum.add_assign(el));

        if round < params.rounds - 1 {
            for (el, rc) in input.iter_mut().zip(params.round_constants[round].iter()) {
                el.add_assign(&sum);
                el.add_assign(rc);
            }
        } else {
            for el in input.iter_mut() {
                el.add_assign(&sum);
            }
        }
    }

    fn affine_4<F: PrimeField>(params: &GriffinParams<F>, input: &mut [F], round: usize) {
        let mut t_0 = input[0];
        t_0.add_assign(&input[1]);
        let mut t_1 = input[2];
        t_1.add_assign(&input[3]);
        let mut t_2 = input[1];
        t_2.double_in_place();
        t_2.add_assign(&t_1);
        let mut t_3 = input[3];
        t_3.double_in_place();
        t_3.add_assign(&t_0);
        let mut t_4 = t_1;
        t_4.double_in_place();
        t_4.double_in_place();
        t_4.add_assign(&t_3);
        let mut t_5 = t_0;
        t_5.double_in_place();
        t_5.double_in_place();
        t_5.add_assign(&t_2);
        let mut t_6 = t_3;
        t_6.add_assign(&t_5);
        let mut t_7 = t_2;
        t_7.add_assign(&t_4);
        input[0] = t_6;
        input[1] = t_5;
        input[2] = t_7;
        input[3] = t_4;

        if round < params.rounds - 1 {
            for (i, rc) in input.iter_mut().zip(params.round_constants[round].iter()) {
                i.add_assign(rc);
            }
        }
    }

    fn affine<F: PrimeField>(params: &GriffinParams<F>, input: &mut [F], round: usize) {
        if params.t == 3 {
            Griffin::affine_3(params, input, round);
            return;
        }
        if params.t == 4 {
            Griffin::affine_4(params, input, round);
            return;
        }

        let t4 = params.t / 4;
        for i in 0..t4 {
            let start_index = i * 4;
            let mut t_0 = input[start_index];
            t_0.add_assign(&input[start_index + 1]);
            let mut t_1 = input[start_index + 2];
            t_1.add_assign(&input[start_index + 3]);
            let mut t_2 = input[start_index + 1];
            t_2.double_in_place();
            t_2.add_assign(&t_1);
            let mut t_3 = input[start_index + 3];
            t_3.double_in_place();
            t_3.add_assign(&t_0);
            let mut t_4: F = t_1;
            t_4.double_in_place();
            t_4.double_in_place();
            t_4.add_assign(&t_3);
            let mut t_5 = t_0;
            t_5.double_in_place();
            t_5.double_in_place();
            t_5.add_assign(&t_2);
            input[start_index] = t_3 + t_5;
            input[start_index + 1] = t_5;
            input[start_index + 2] = t_2 + t_4;
            input[start_index + 3] = t_4;
        }

        let mut stored = [F::zero(); 4];
        for l in 0..4 {
            stored[l] = input[l];
            for j in 1..t4 {
                stored[l].add_assign(&input[4 * j + l]);
            }
        }

        for i in 0..input.len() {
            input[i].add_assign(&stored[i % 4]);
            if round < params.rounds - 1 {
                input[i].add_assign(&params.round_constants[round][i]);
            }
        }
    }

    fn non_linear<F: PrimeField>(params: &GriffinParams<F>, input: &mut [F]) {
        input[0] = {
            let mut res = F::one();
            for &i in &params.d_inv {
                res.square_in_place();
                if i {
                    res *= input[0];
                }
            }
            res
        };

        let mut state = input[1];

        input[1].square_in_place();
        match params.d {
            3 => {}
            5 => {
                input[1].square_in_place();
            }
            _ => panic!(),
        }
        input[1].mul_assign(&state);

        let mut y01_i = input[1];
        for i in 2..input.len() {
            y01_i += input[0];
            let l = if i == 2 { y01_i } else { y01_i + state };
            let ab = &params.alpha_beta[i - 2];
            state = input[i];
            input[i] *= l.square() + l * ab[0] + ab[1];
        }
    }

    pub fn permute<F: PrimeField>(params: &GriffinParams<F>, input: &mut [F]) {
        Griffin::affine(params, input, params.rounds);

        for r in 0..params.rounds {
            Griffin::non_linear(params, input);
            Griffin::affine(params, input, r);
        }
    }

    pub fn hash<F: PrimeField>(params: &GriffinParams<F>, message: &[F]) -> F {
        let mut state = vec![F::zero(); params.t];
        for chunk in message.chunks(params.rate) {
            for i in 0..chunk.len() {
                state[i] += &chunk[i];
            }
            Griffin::permute(params, &mut state)
        }
        state[0]
    }
}

pub struct GriffinGadget;

impl GriffinGadget {
    fn non_linear<F: PrimeField>(
        params: &GriffinParams<F>,
        state: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let cs = state.cs();
        let mut result = state.to_owned();
        result[0] = FpVar::new_variable_with_inferred_mode(cs, || {
            assignment_or_setup(result[0].cs(), F::zero, || {
                let v = result[0].value()?;
                let mut res = F::one();
                for &i in &params.d_inv {
                    res.square_in_place();
                    if i {
                        res *= v;
                    }
                }
                Ok(res)
            })
        })?;

        let mut sq = result[0].square()?;
        if params.d == 5 {
            sq = sq.square()?;
        }
        result[0].mul_equals(&sq, &state[0])?;

        let mut sq = result[1].square()?;
        if params.d == 5 {
            sq = sq.square()?;
        }
        result[1] *= sq;

        let mut y01_i = result[1].clone();

        for i in 2..result.len() {
            y01_i += &result[0];
            let l = if i == 2 {
                y01_i.clone()
            } else {
                &y01_i + &state[i - 1]
            };
            let ab = &params.alpha_beta[i - 2];
            result[i] *= l.square()? + l * ab[0] + ab[1];
        }

        Ok(result)
    }

    pub fn permute<F: PrimeField>(
        params: &GriffinParams<F>,
        state: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut current_state = state.to_owned();
        current_state = params
            .mat
            .iter()
            .map(|row| current_state.iter().zip(row).map(|(a, b)| a * *b).sum())
            .collect();

        for r in 0..params.rounds {
            current_state = GriffinGadget::non_linear(params, &current_state)?;
            current_state = params
                .mat
                .iter()
                .map(|row| current_state.iter().zip(row).map(|(a, b)| a * *b).sum())
                .collect();
            if r < params.rounds - 1 {
                current_state = current_state
                    .iter()
                    .zip(&params.round_constants[r])
                    .map(|(c, rc)| c + *rc)
                    .collect();
            }
        }
        Ok(current_state)
    }

    pub fn hash<F: PrimeField>(
        params: &GriffinParams<F>,
        message: &[FpVar<F>],
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut state = vec![FpVar::zero(); params.t];
        for chunk in message.chunks(params.rate) {
            for i in 0..chunk.len() {
                state[i] += &chunk[i];
            }
            state = GriffinGadget::permute(params, &state)?;
        }
        Ok(state[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{error::Error, rand::thread_rng};
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn test_hash_matches_gadget() -> Result<(), Box<dyn Error>> {
        let rng = &mut thread_rng();
        let params = GriffinParams::new(24, 5, 9);
        let t = params.t;
        let x: Vec<Fr> = (0..t).map(|_| Fr::rand(rng)).collect();

        let y = Griffin::hash(&params, &x);

        let cs = ConstraintSystem::new_ref();
        let x_var = Vec::new_witness(cs.clone(), || Ok(x.clone()))?;
        let y_var = GriffinGadget::hash(&params, &x_var)?;
        assert_eq!(y, y_var.value()?);
        println!("{}", cs.num_constraints());
        assert!(cs.is_satisfied()?);

        Ok(())
    }

    #[test]
    fn test_permutation_is_deterministic() {
        let rng = &mut thread_rng();
        let params = GriffinParams::new(3, 5, 12);
        let t = params.t;
        for _ in 0..5 {
            let input1: Vec<_> = (0..t).map(|_| Fr::rand(rng)).collect();

            let mut input2: Vec<_>;
            loop {
                input2 = (0..t).map(|_| Fr::rand(rng)).collect();
                if input1 != input2 {
                    break;
                }
            }

            let mut perm1 = input1.clone();
            let mut perm2 = input1.clone();
            let mut perm3 = input2.clone();
            Griffin::permute(&params, &mut perm1);
            Griffin::permute(&params, &mut perm2);
            Griffin::permute(&params, &mut perm3);
            assert_eq!(perm1, perm2);
            assert_ne!(perm1, perm3);
        }
    }

    fn multiply_matrix_by_vector<F: PrimeField>(input: &[F], mat: &[Vec<F>]) -> Vec<F> {
        let t = mat.len();
        debug_assert!(t == input.len());
        let mut out = vec![F::zero(); t];
        for row in 0..t {
            for (col, inp) in input.iter().enumerate() {
                let mut tmp = mat[row][col];
                tmp *= inp;
                out[row] += &tmp;
            }
        }
        out
    }

    fn check_affine_matches_matrix<F: PrimeField>(t: usize) {
        let rng = &mut thread_rng();
        let params = GriffinParams::<F>::new(t, 5, 1);

        let mat = &params.mat;

        for _ in 0..5 {
            let input: Vec<F> = (0..t).map(|_| F::rand(rng)).collect();

            let output1 = multiply_matrix_by_vector(&input, mat);
            let mut output2 = input.to_owned();
            Griffin::affine(&params, &mut output2, 1);
            assert_eq!(output1, output2);
        }
    }

    #[test]
    fn test_affine_3() {
        check_affine_matches_matrix::<Fr>(3);
    }

    #[test]
    fn test_affine_4() {
        check_affine_matches_matrix::<Fr>(4);
    }

    #[test]
    fn test_affine_8() {
        check_affine_matches_matrix::<Fr>(8);
    }

    #[test]
    fn test_affine_60() {
        check_affine_matches_matrix::<Fr>(60);
    }
}
