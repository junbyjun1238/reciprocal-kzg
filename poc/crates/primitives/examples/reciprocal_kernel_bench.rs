use std::{hint::black_box, time::Instant};

use ark_bn254::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_std::rand::{SeedableRng, rngs::StdRng};

type BaseField = Fr;
type Ambient = [BaseField; 4];
type State = [BaseField; 4];
type Matrix = [[BaseField; 4]; 4];

#[derive(Clone, Debug)]
struct KernelBenchRow {
    depth: usize,
    leaves: usize,
    reduced_descriptor_words: usize,
    explicit_row_words: usize,
    descriptor_word_ratio: String,
    specialized_mults: usize,
    direct_mults: usize,
    mult_ratio: String,
    expand_us: u128,
    row_materialize_us: u128,
    specialized_eval_us: u128,
    direct_eval_us: u128,
    row_eval_us: u128,
}

impl KernelBenchRow {
    fn csv_header() -> &'static str {
        "depth,leaves,reduced_descriptor_words,explicit_row_words,descriptor_word_ratio,specialized_mults,direct_mults,mult_ratio,expand_us,row_materialize_us,specialized_eval_us,direct_eval_us,row_eval_us"
    }

    fn csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.depth,
            self.leaves,
            self.reduced_descriptor_words,
            self.explicit_row_words,
            self.descriptor_word_ratio,
            self.specialized_mults,
            self.direct_mults,
            self.mult_ratio,
            self.expand_us,
            self.row_materialize_us,
            self.specialized_eval_us,
            self.direct_eval_us,
            self.row_eval_us,
        )
    }
}

#[derive(Clone)]
struct ExpandedReciprocalData {
    mu_by_round: Vec<[BaseField; 4]>,
    r_by_round: Vec<Ambient>,
    delta_terminal: Ambient,
}

fn zero() -> BaseField {
    BaseField::zero()
}

fn one() -> BaseField {
    BaseField::one()
}

fn ambient_zero() -> Ambient {
    [zero(); 4]
}

fn ambient_one() -> Ambient {
    [one(), zero(), zero(), zero()]
}

fn initial_orbit_point() -> Ambient {
    [zero(), one(), zero(), zero()]
}

fn scalar_in_ambient(value: BaseField) -> Ambient {
    [value, zero(), zero(), zero()]
}

fn ambient_add(lhs: &Ambient, rhs: &Ambient) -> Ambient {
    core::array::from_fn(|i| lhs[i] + rhs[i])
}

fn ambient_sub(lhs: &Ambient, rhs: &Ambient) -> Ambient {
    core::array::from_fn(|i| lhs[i] - rhs[i])
}

fn ambient_sub_scalar(lhs: &Ambient, rhs: BaseField) -> Ambient {
    [lhs[0] - rhs, lhs[1], lhs[2], lhs[3]]
}

fn ambient_scale(value: &Ambient, scalar: BaseField) -> Ambient {
    core::array::from_fn(|i| value[i] * scalar)
}

fn ambient_mul(mu_seed: [BaseField; 4], lhs: &Ambient, rhs: &Ambient) -> Ambient {
    let mut raw = [zero(); 7];
    for i in 0..4 {
        for j in 0..4 {
            raw[i + j] += lhs[i] * rhs[j];
        }
    }

    for degree in (4..=6).rev() {
        let coeff = raw[degree];
        if coeff.is_zero() {
            continue;
        }
        for k in 0..4 {
            raw[degree - 4 + k] += coeff * mu_seed[k];
        }
        raw[degree] = zero();
    }

    [raw[0], raw[1], raw[2], raw[3]]
}

fn ambient_square(mu_seed: [BaseField; 4], value: &Ambient) -> Ambient {
    ambient_mul(mu_seed, value, value)
}

fn ambient_cube(mu_seed: [BaseField; 4], value: &Ambient) -> Ambient {
    ambient_mul(mu_seed, &ambient_square(mu_seed, value), value)
}

fn build_multiplication_matrix(mu_seed: [BaseField; 4], public_value: &Ambient) -> Matrix {
    let mut matrix = [[zero(); 4]; 4];
    for column in 0..4 {
        let mut basis = ambient_zero();
        basis[column] = one();
        let image = ambient_mul(mu_seed, public_value, &basis);
        for row in 0..4 {
            matrix[row][column] = image[row];
        }
    }
    matrix
}

fn solve_linear_system_4x4(matrix: Matrix, rhs: Ambient) -> Option<Ambient> {
    let mut augmented = [[zero(); 5]; 4];
    for row in 0..4 {
        for column in 0..4 {
            augmented[row][column] = matrix[row][column];
        }
        augmented[row][4] = rhs[row];
    }

    for pivot_col in 0..4 {
        let pivot_row = (pivot_col..4).find(|&row| !augmented[row][pivot_col].is_zero())?;
        if pivot_row != pivot_col {
            augmented.swap(pivot_col, pivot_row);
        }

        let pivot_inv = augmented[pivot_col][pivot_col].inverse()?;
        for column in pivot_col..5 {
            augmented[pivot_col][column] *= pivot_inv;
        }

        for row in 0..4 {
            if row == pivot_col {
                continue;
            }
            let factor = augmented[row][pivot_col];
            if factor.is_zero() {
                continue;
            }
            for column in pivot_col..5 {
                augmented[row][column] -= factor * augmented[pivot_col][column];
            }
        }
    }

    Some([
        augmented[0][4],
        augmented[1][4],
        augmented[2][4],
        augmented[3][4],
    ])
}

fn ambient_inverse(mu_seed: [BaseField; 4], value: &Ambient) -> Option<Ambient> {
    solve_linear_system_4x4(build_multiplication_matrix(mu_seed, value), ambient_one())
}

fn reciprocal_shift_descriptor_update(
    mu_i: [BaseField; 4],
    c: BaseField,
) -> Result<[BaseField; 4], String> {
    let c2 = c * c;
    let c3 = c2 * c;
    let c4 = c3 * c;
    let d_c = c4 - mu_i[3] * c3 - mu_i[2] * c2 - mu_i[1] * c - mu_i[0];
    let d_inv = d_c
        .inverse()
        .ok_or_else(|| "singular reciprocal-shift descriptor update".to_owned())?;
    Ok([
        -d_inv,
        (mu_i[3] - BaseField::from(4_u64) * c) * d_inv,
        (mu_i[2] + BaseField::from(3_u64) * c * mu_i[3] - BaseField::from(6_u64) * c2) * d_inv,
        (mu_i[1] + BaseField::from(2_u64) * c * mu_i[2] + BaseField::from(3_u64) * c2 * mu_i[3]
            - BaseField::from(4_u64) * c3)
            * d_inv,
    ])
}

fn round_shift(round: usize) -> BaseField {
    if round % 2 == 1 { zero() } else { one() }
}

fn expand_reciprocal_data(
    depth: usize,
    mu_seed: [BaseField; 4],
) -> Result<ExpandedReciprocalData, String> {
    let mut mu_by_round = Vec::with_capacity(depth);
    let mut r_by_round = Vec::with_capacity(depth + 1);
    let mut current_mu = mu_seed;
    let mut current_r = initial_orbit_point();
    let mut delta = ambient_one();

    mu_by_round.push(current_mu);
    r_by_round.push(current_r);

    for round in 1..=depth {
        let c = round_shift(round);
        let shifted = ambient_sub_scalar(&current_r, c);
        let next_r = ambient_inverse(mu_seed, &shifted)
            .ok_or_else(|| format!("orbit inversion failed at round {round}"))?;
        delta = ambient_mul(mu_seed, &delta, &ambient_cube(mu_seed, &next_r));
        r_by_round.push(next_r);

        if round < depth {
            current_mu = reciprocal_shift_descriptor_update(current_mu, c)?;
            mu_by_round.push(current_mu);
        }

        current_r = next_r;
    }

    Ok(ExpandedReciprocalData {
        mu_by_round,
        r_by_round,
        delta_terminal: delta,
    })
}

fn fold_pair_specialized(mu_i: [BaseField; 4], round: usize, lhs: State, rhs: State) -> State {
    let delta0 = rhs[0] - lhs[0];
    let delta1 = rhs[1] - lhs[1];
    let delta2 = rhs[2] - lhs[2];
    let delta3 = rhs[3] - lhs[3];

    let u0 = lhs[0] + mu_i[0] * delta3;
    let u1 = lhs[1] + delta0 + mu_i[1] * delta3;
    let u2 = lhs[2] + delta1 + mu_i[2] * delta3;
    let u3 = lhs[3] + delta2 + mu_i[3] * delta3;

    if round % 2 == 1 {
        [u3, u2, u1, u0]
    } else {
        let two_u2 = u2 + u2;
        let three_u3 = u3 + u3 + u3;
        [u3, u2 + three_u3, u1 + two_u2 + three_u3, u0 + u1 + u2 + u3]
    }
}

fn run_specialized_kernel(mu_by_round: &[[BaseField; 4]], leaves: &[BaseField]) -> State {
    assert!(leaves.len().is_power_of_two());
    assert_eq!(1_usize << mu_by_round.len(), leaves.len());

    let mut layer: Vec<State> = leaves
        .chunks_exact(2)
        .map(|pair| [zero(), zero(), pair[1] - pair[0], pair[0]])
        .collect();

    for round in 2..=mu_by_round.len() {
        let mu_i = mu_by_round[round - 1];
        layer = layer
            .chunks_exact(2)
            .map(|pair| fold_pair_specialized(mu_i, round, pair[0], pair[1]))
            .collect();
    }

    layer[0]
}

fn reconstruct_terminal_value(
    mu_seed: [BaseField; 4],
    state: State,
    terminal_r: &Ambient,
    delta_terminal: &Ambient,
) -> Ambient {
    let r2 = ambient_square(mu_seed, terminal_r);
    let r3 = ambient_mul(mu_seed, &r2, terminal_r);
    let numerator = ambient_add(
        &ambient_add(
            &scalar_in_ambient(state[0]),
            &ambient_scale(terminal_r, state[1]),
        ),
        &ambient_add(&ambient_scale(&r2, state[2]), &ambient_scale(&r3, state[3])),
    );
    let delta_inv = ambient_inverse(mu_seed, delta_terminal)
        .expect("shared denominator should stay invertible");
    ambient_mul(mu_seed, &delta_inv, &numerator)
}

fn multiply_matrix_by_ambient(matrix: &Matrix, vector: &Ambient) -> Ambient {
    let mut out = ambient_zero();
    for row in 0..4 {
        let mut acc = zero();
        for column in 0..4 {
            acc += matrix[row][column] * vector[column];
        }
        out[row] = acc;
    }
    out
}

fn run_direct_basis_kernel(
    mu_seed: [BaseField; 4],
    r_by_round: &[Ambient],
    leaves: &[BaseField],
) -> Ambient {
    assert!(leaves.len().is_power_of_two());
    let mut layer: Vec<Ambient> = leaves.iter().copied().map(scalar_in_ambient).collect();

    for (round_index, public_r) in r_by_round.iter().take(r_by_round.len() - 1).enumerate() {
        let round = round_index + 1;
        if round == 1 {
            layer = layer
                .chunks_exact(2)
                .map(|pair| {
                    let delta_scalar = pair[1][0] - pair[0][0];
                    ambient_add(&pair[0], &ambient_scale(public_r, delta_scalar))
                })
                .collect();
        } else {
            let matrix = build_multiplication_matrix(mu_seed, public_r);
            layer = layer
                .chunks_exact(2)
                .map(|pair| {
                    let delta = ambient_sub(&pair[1], &pair[0]);
                    ambient_add(&pair[0], &multiply_matrix_by_ambient(&matrix, &delta))
                })
                .collect();
        }
    }

    layer[0]
}

fn basis_state(index: usize) -> State {
    let mut basis = [zero(); 4];
    basis[index] = one();
    basis
}

fn zero_state() -> State {
    [zero(); 4]
}

fn build_branch_matrix(mu_i: [BaseField; 4], round: usize, right_branch: bool) -> Matrix {
    let mut matrix = [[zero(); 4]; 4];
    for column in 0..4 {
        let column_state = if right_branch {
            fold_pair_specialized(mu_i, round, zero_state(), basis_state(column))
        } else {
            fold_pair_specialized(mu_i, round, basis_state(column), zero_state())
        };
        for row in 0..4 {
            matrix[row][column] = column_state[row];
        }
    }
    matrix
}

fn multiply_matrix_by_state(matrix: &Matrix, vector: &State) -> State {
    let mut out = [zero(); 4];
    for row in 0..4 {
        let mut acc = zero();
        for column in 0..4 {
            acc += matrix[row][column] * vector[column];
        }
        out[row] = acc;
    }
    out
}

fn build_materialized_columns(mu_by_round: &[[BaseField; 4]]) -> Vec<State> {
    let depth = mu_by_round.len();
    if depth == 1 {
        return vec![
            [zero(), zero(), -one(), one()],
            [zero(), zero(), one(), zero()],
        ];
    }

    let mut columns = vec![
        [zero(), zero(), -one(), one()],
        [zero(), zero(), one(), zero()],
    ];

    for round in 2..=depth {
        let mu_i = mu_by_round[round - 1];
        let left = build_branch_matrix(mu_i, round, false);
        let right = build_branch_matrix(mu_i, round, true);

        let mut next = Vec::with_capacity(columns.len() * 2);
        for column in &columns {
            next.push(multiply_matrix_by_state(&left, column));
        }
        for column in &columns {
            next.push(multiply_matrix_by_state(&right, column));
        }
        columns = next;
    }

    columns
}

fn evaluate_with_materialized_columns(columns: &[State], leaves: &[BaseField]) -> State {
    let mut out = [zero(); 4];
    for (column, leaf) in columns.iter().zip(leaves.iter().copied()) {
        for row in 0..4 {
            out[row] += column[row] * leaf;
        }
    }
    out
}

fn sample_seed_descriptor() -> [BaseField; 4] {
    [
        BaseField::from(1_u64),
        -BaseField::from(4_u64),
        -BaseField::from(3_u64),
        -BaseField::from(2_u64),
    ]
}

fn benchmark_average_us<R>(repeats: usize, mut f: impl FnMut() -> R) -> u128 {
    let start = Instant::now();
    for _ in 0..repeats {
        black_box(f());
    }
    start.elapsed().as_micros() / repeats as u128
}

fn repeats_for_problem_size(problem_size: usize, target_work: usize, min_repeats: usize) -> usize {
    min_repeats.max(target_work / problem_size.max(1))
}

fn format_ratio(numerator: usize, denominator: usize) -> String {
    format!("{:.2}", numerator as f64 / denominator as f64)
}

fn assert_specialized_matches_direct(
    mu_seed: [BaseField; 4],
    expanded: &ExpandedReciprocalData,
    leaves: &[BaseField],
) -> State {
    let specialized_state = run_specialized_kernel(&expanded.mu_by_round, leaves);
    let direct_terminal = run_direct_basis_kernel(mu_seed, &expanded.r_by_round, leaves);
    let reconstructed = reconstruct_terminal_value(
        mu_seed,
        specialized_state,
        expanded
            .r_by_round
            .last()
            .expect("terminal orbit point should exist"),
        &expanded.delta_terminal,
    );
    assert_eq!(reconstructed, direct_terminal);
    specialized_state
}

fn materialize_verified_columns(
    expanded: &ExpandedReciprocalData,
    leaves: &[BaseField],
    specialized_state: State,
) -> Vec<State> {
    let columns = build_materialized_columns(&expanded.mu_by_round);
    let row_state = evaluate_with_materialized_columns(&columns, leaves);
    assert_eq!(row_state, specialized_state);
    columns
}

fn benchmark_row(
    depth: usize,
    mu_seed: [BaseField; 4],
    rng: &mut StdRng,
) -> Result<KernelBenchRow, String> {
    let leaf_count = 1_usize << depth;
    let leaves: Vec<BaseField> = (0..leaf_count).map(|_| BaseField::rand(rng)).collect();

    let expand_start = Instant::now();
    let expanded = expand_reciprocal_data(depth, mu_seed)?;
    let expand_us = expand_start.elapsed().as_micros();

    let specialized_state = assert_specialized_matches_direct(mu_seed, &expanded, &leaves);
    let columns = materialize_verified_columns(&expanded, &leaves, specialized_state);

    let eval_repeats = repeats_for_problem_size(leaf_count, 1 << 20, 8);
    let materialize_repeats = repeats_for_problem_size(leaf_count, 1 << 18, 4);
    let specialized_eval_us = benchmark_average_us(eval_repeats, || {
        run_specialized_kernel(&expanded.mu_by_round, black_box(&leaves))
    });
    let direct_eval_us = benchmark_average_us(eval_repeats, || {
        run_direct_basis_kernel(mu_seed, black_box(&expanded.r_by_round), black_box(&leaves))
    });
    let row_materialize_us = benchmark_average_us(materialize_repeats, || {
        build_materialized_columns(black_box(&expanded.mu_by_round))
    });
    let row_eval_us = benchmark_average_us(eval_repeats, || {
        evaluate_with_materialized_columns(black_box(&columns), black_box(&leaves))
    });

    let reduced_descriptor_words = 4 * (depth - 1);
    let explicit_row_words = 4 * leaf_count;
    let specialized_mults = 2 * leaf_count - 4;
    let direct_mults = 10 * leaf_count - 16;

    Ok(KernelBenchRow {
        depth,
        leaves: leaf_count,
        reduced_descriptor_words,
        explicit_row_words,
        descriptor_word_ratio: format_ratio(explicit_row_words, reduced_descriptor_words),
        specialized_mults,
        direct_mults,
        mult_ratio: format_ratio(direct_mults, specialized_mults),
        expand_us,
        row_materialize_us,
        specialized_eval_us,
        direct_eval_us,
        row_eval_us,
    })
}

fn main() -> Result<(), String> {
    let mu_seed = sample_seed_descriptor();
    let mut rng = StdRng::seed_from_u64(0xDEC0DED);
    let depths = [2_usize, 4, 8, 10, 12, 14, 16];

    println!(
        "# reciprocal kernel benchmark (release build recommended)\n# specialized physical fold vs direct fixed-basis baseline vs explicit-row materialization"
    );
    println!("{}", KernelBenchRow::csv_header());

    for depth in depths {
        let row = benchmark_row(depth, mu_seed, &mut rng)?;
        println!("{}", row.csv_row());
    }

    println!(
        "\n# notes\n# specialized_mults follows the paper's canonical 2N-4 count\n# direct_mults uses the direct fixed-basis public-constant baseline: 4 multiplications per pair in round 1, then 16 per surviving pair"
    );

    Ok(())
}
