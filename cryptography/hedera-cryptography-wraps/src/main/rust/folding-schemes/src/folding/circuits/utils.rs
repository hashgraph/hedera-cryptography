use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::gr1cs::SynthesisError;
use std::marker::PhantomData;

/// EqEval is a gadget for computing $\tilde{eq}(a, b) = \prod_{i=1}^{l}(a_i \cdot b_i + (1 - a_i)(1 - b_i))$
/// :warning: This is not the ark_r1cs_std::eq::EqGadget
pub struct EqEvalGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> EqEvalGadget<F> {
    /// Gadget to evaluate eq polynomial.
    /// Follows the implementation of `eq_eval` found in this crate.
    pub fn eq_eval(x: &[FpVar<F>], y: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        if x.len() != y.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if x.is_empty() || y.is_empty() {
            return Err(SynthesisError::AssignmentMissing);
        }
        let mut e = FpVar::<F>::one();
        for (xi, yi) in x.iter().zip(y.iter()) {
            let xi_yi = xi * yi;
            e *= xi_yi.clone() + xi_yi - xi - yi + F::one();
        }
        Ok(e)
    }
}