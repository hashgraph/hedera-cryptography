// SPDX-License-Identifier: Apache-2.0

use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain,
};
use ark_std::ops::*;

/// returns the vanishing polynomial for a multiplicative subgroup of size n;
/// when n is a power of 2, this is equivalent to t(X) = X^n - 1
pub fn compute_vanishing_poly<F: PrimeField + From<u64>>(
    n: usize
) -> DensePolynomial<F> {
    let mut coeffs = vec![];
    for i in 0..n + 1 {
        if i == 0 {
            let minus_one: F = F::from(0u64) - F::from(1u64);
            coeffs.push(minus_one); // 0'th coefficient is -1
        } else if i < n {
            coeffs.push(F::from(0u64)); // all other coefficients are 0
        } else {
            coeffs.push(F::from(1u64)); // n'th coefficient is 1 for X^n
        }
    }
    DensePolynomial { coeffs }
}

/// computes the polynomial which evaluates to points in the input vector evals using interpolation;
/// the domain is the powers of n-th root of unity, where n is size of the evals vector (power of 2)
pub fn interpolate_poly_over_mult_subgroup<F: PrimeField + From<u64>>(
    evals: &Vec<F>,
) -> Option<DensePolynomial<F>> {
    Radix2EvaluationDomain::<F>::new(evals.len()).map(|d| {
        Evaluations::from_vec_and_domain(evals.clone(), d).interpolate()
    })
}

/// outputs the Lagrange polynomial for the ith location in a multiplicative subgroup
/// of size n, defined to be 1 at omega^i and 0 elsewhere on domain
/// {omega^i}_{i \in [n]} (where omega is the n-th root of unity)
pub fn lagrange_poly<F: PrimeField + From<u64>>(
    n: usize,
    i: usize
) -> Option<DensePolynomial<F>> {
    // see sec 3 of https://eprint.iacr.org/2023/567.pdf
    nth_root_of_unity::<F>(n).map(|ω| {
        let factor = ω.pow([i as u64]) / F::from(n as u64);

        let numerator = compute_vanishing_poly(n);
        let denominator = {
            let mut coeffs = vec![];
            coeffs.push(F::from(0u64) - ω.pow([i as u64])); // -ω^i
            coeffs.push(F::from(1u64)); // X
            DensePolynomial { coeffs }
        };

        poly_eval_mult_c(&numerator, &factor).div(&denominator)
    })
}

/// returns t(X) = X
pub fn compute_x_monomial<F: PrimeField + From<u64>>() -> DensePolynomial<F> {
    let mut coeffs = vec![];
    coeffs.push(F::from(0u64)); // 0
    coeffs.push(F::from(1u64)); // X
    DensePolynomial { coeffs }
}

/// returns t(X) = c
pub fn compute_constant_poly<F: PrimeField>(c: &F) -> DensePolynomial<F> {
    let mut coeffs = vec![];
    coeffs.push(c.clone()); // c
    DensePolynomial { coeffs }
}

/// computes f(ωx)
pub fn poly_domain_mult_ω<F: PrimeField>(f: &DensePolynomial<F>, ω: &F) -> DensePolynomial<F> {
    let mut new_poly = f.clone();
    for i in 1..(f.degree() + 1) {
        //we don't touch the zeroth coefficient
        let ω_pow_i: F = ω.pow([i as u64]);
        new_poly.coeffs[i] = new_poly.coeffs[i] * ω_pow_i;
    }
    new_poly
}

/// computes polynomial c . f(x), for some constant c and input polynomial f(x)
pub fn poly_eval_mult_c<F: PrimeField>(f: &DensePolynomial<F>, c: &F) -> DensePolynomial<F> {
    let mut new_poly = f.clone();
    for i in 0..(f.degree() + 1) {
        new_poly.coeffs[i] = new_poly.coeffs[i] * c.clone();
    }
    new_poly
}

/// outputs a generator of the multiplicative subgroup of input size n
pub fn nth_root_of_unity<F: PrimeField>(n: usize) -> Option<F> {
    Radix2EvaluationDomain::<F>::new(n).map(|d| d.group_gen)
}

/// checks whether n is at least 2 and a power of 2
pub fn is_n_valid(n: usize) -> bool {
    n > 1 && (n & (n - 1)) == 0
}
