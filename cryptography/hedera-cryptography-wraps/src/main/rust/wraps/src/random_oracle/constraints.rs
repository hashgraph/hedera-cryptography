// SPDX-License-Identifier: Apache-2.0
// Portions of this file are derived from arkworks-rs/r1cs-tutorial under Apache 2.0 License.

use core::fmt::Debug;
use ark_ff::Field;
use ark_relations::gr1cs::SynthesisError;
use ark_r1cs_std::prelude::*;

use crate::random_oracle::RandomOracle;

pub trait RandomOracleGadget<RO: RandomOracle, ConstraintF: Field>: Sized {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<RO::Output, ConstraintF>
        + GR1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<RO::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}
