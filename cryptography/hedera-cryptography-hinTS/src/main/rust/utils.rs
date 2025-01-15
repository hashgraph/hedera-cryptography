#![allow(dead_code)]

use ark_std::ops::*;
use ark_ff::PrimeField;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use crate::assert_power_of_2;

// returns t(X) = X^n - 1
// relies on n being a power of 2
pub fn compute_vanishing_poly<F: PrimeField + From<u64>>(n: usize) -> DensePolynomial<F> {
    assert_power_of_2!(n);

    let mut coeffs = vec![];
    for i in 0..n+1 {
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

// interpolate polynomial which evaluates to points in v
// the domain is the powers of n-th root of unity, where n is size of v
// relies on n being a power of 2
pub fn interpolate_poly_over_mult_subgroup<F: PrimeField + From<u64>>(evals: &Vec<F>) -> DensePolynomial<F> {
    let n = evals.len();
    assert_power_of_2!(n);

    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(evals.to_owned(), domain);
    eval_form.interpolate()
}

// 1 at omega^i and 0 elsewhere on domain {omega^i}_{i \in [n]}
pub fn lagrange_poly<F: PrimeField + From<u64>>(n: usize, i: usize) -> DensePolynomial<F> {
    assert_power_of_2!(n);

    // see sec 3 of https://eprint.iacr.org/2023/567.pdf
    let ω = nth_root_of_unity::<F>(n);
    let factor = ω.pow([i as u64]) / F::from(n as u64);

    let numerator = compute_vanishing_poly(n);
    let denominator = {
        let mut coeffs = vec![];
        coeffs.push(F::from(0u64) - ω.pow([i as u64])); // -ω^i
        coeffs.push(F::from(1u64)); // X
        DensePolynomial { coeffs }
    };

    poly_eval_mult_c(&numerator, &factor).div(&denominator)
}
// returns t(X) = X
pub fn compute_x_monomial<F: PrimeField + From<u64>>() -> DensePolynomial<F> {
    let mut coeffs = vec![];
    coeffs.push(F::from(0u64)); // 0
    coeffs.push(F::from(1u64)); // X
    DensePolynomial { coeffs }
}

// returns t(X) = c
pub fn compute_constant_poly<F: PrimeField>(c: &F) -> DensePolynomial<F> {
    let mut coeffs = vec![];
    coeffs.push(c.clone()); // c
    DensePolynomial { coeffs }
}

// computes f(ωx)
pub fn poly_domain_mult_ω<F: PrimeField>(f: &DensePolynomial<F>, ω: &F) -> DensePolynomial<F> {
    let mut new_poly = f.clone();
    for i in 1..(f.degree() + 1) { //we don't touch the zeroth coefficient
        let ω_pow_i: F = ω.pow([i as u64]);
        new_poly.coeffs[i] = new_poly.coeffs[i] * ω_pow_i;
    }
    new_poly
}

// computes c . f(x), for some constnt c
pub fn poly_eval_mult_c<F: PrimeField>(f: &DensePolynomial<F>, c: &F) -> DensePolynomial<F> {
    let mut new_poly = f.clone();
    for i in 0..(f.degree() + 1) {
        new_poly.coeffs[i] = new_poly.coeffs[i] * c.clone();
    }
    new_poly
}

// returns a generator of the multiplicative subgroup of input size n
pub fn nth_root_of_unity<F: PrimeField>(n: usize) -> F {
    assert_power_of_2!(n);

    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    domain.group_gen
}

#[macro_export]
macro_rules! assert_power_of_2 {
    ($x:expr) => {
        assert!($x > 0 && ($x & ($x - 1)) == 0, "{} is not a power of 2", $x);
    };
}

#[macro_export]
macro_rules! check_or_return_false {
    ($cond:expr) => {
        if !$cond {
            return false;
        }
    };
}