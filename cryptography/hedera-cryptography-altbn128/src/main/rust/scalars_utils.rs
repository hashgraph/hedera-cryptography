//
// Copyright (C) 2024 Hedera Hashgraph, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::Rng;

/// Generic utility functions to instantiate scalars (fr)
/// In summary:
/// Fq defines the coordinate field for the points on the curve (where the curve is drawn).
/// Fr defines the field for the scalars used in operations on the curve, typically corresponding to the prime order of a subgroup of points on the curve.

pub type F = ark_bn254::Fr;
pub type ScalarField<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;

/// creates a scalar from an u8 array reference, if the integer represented by the input is bigger than the field the appropriate reduction is performed
pub fn scalars_from_bytes(value: &[u8]) -> F {
    F::from_le_bytes_mod_order(&value)
}

/// Same as before but extracts F from the curve config
pub fn scalars_curve_from_bytes<G: CurveGroup>(value: &[u8]) -> ScalarField<G> {
    ScalarField::<G>::from_le_bytes_mod_order(&value)
}

/// creates an u8 vector from a scalar
pub fn scalars_to_bytes(value: F) -> Result<Vec<u8>, String> {
    let mut serialized = Vec::new();
    match value.serialize_uncompressed(&mut serialized) {
        Ok(_) => Ok(serialized),
        Err(v) => Err(v.to_string()),
    }
}

/// creates a 0 scalar value
pub fn scalars_zero() -> F {
    F::zero()
}

/// creates a 1 scalar value
pub fn scalars_one() -> F {
    F::one()
}

/// creates a scalar from an initialized random number generator
pub fn scalars_from_random<R: Rng>(rng: &mut R) -> F {
    F::rand(rng)
}

/// creates a scalar from an u64
pub fn scalars_from_u64(value: u64) -> F {
    F::from(value)
}

/// Inverses the scalar. It returns a result object, error means that it could not be inverted e.g. the value was 0.
pub fn scalars_inverse(value: F) -> Result<F, String> {
    match value.inverse() {
        Some(value) => Ok(value),
        None => Err("Value cannot be inverted".to_string()),
    }
}

/// powers the scalar to the exponent u64 value
pub fn scalars_pow(value: F, exponent: u64) -> F {
    value.pow([exponent])
}

/// adds two scalars and returns the result
pub fn scalars_add(value: F, value2: F) -> F {
    value + value2
}

/// subtracts two scalars and returns the result
pub fn scalars_minus(value: F, value2: F) -> F {
    value - value2
}

/// multiplies two scalars and returns the result
pub fn scalars_multiply(value: F, value2: F) -> F {
    value * value2
}
