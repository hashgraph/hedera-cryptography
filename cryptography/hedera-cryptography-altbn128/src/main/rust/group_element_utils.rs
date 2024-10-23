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
use ark_serialize::CanonicalDeserialize;
use rand::Rng;
/// Generic utility functions to instantiate and operate with curve points

/// The Scalar field. It is the same Fr as bn254_field_elements. Fr is always [0,1,...r-1].
type ScalarField<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;

/// *********
/// Factories
/// *********

/// returns the 0 point
pub fn group_elements_zero<G: CurveGroup>() -> G {
    G::zero()
}

/// returns the generator of the group
pub fn group_elements_generator<G: CurveGroup>() -> G {
    G::generator()
}

/// returns a random point
pub fn group_elements_from_random<G: CurveGroup, R: Rng>(rng: &mut R) -> G {
    G::rand(rng)
}

/// **********
/// Operations
/// **********

/// addition operation between two points
pub fn group_elements_add<G: CurveGroup>(value: G, value2: G) -> G {
    value + value2
}

/// multiplies a point with a scalar, ark uses this annotation to represent pow
pub fn group_elements_scalar_multiply<G: CurveGroup>(value: G, value2: ScalarField<G>) -> G {
    value.mul(value2)
}

/// returns the total sum of all the point in a collection
pub fn group_elements_total_sum<G: CurveGroup>(values: Vec<G>) -> G {
    values.iter().fold(G::zero(), |acc, point| acc + point)
}

/// given a collection of N scalars, return a generator element multiplied by each of the scalars in the collection
pub fn group_elements_batch_multiply<G: CurveGroup>(values: Vec<ScalarField<G>>) -> Vec<G> {
    let generator = G::generator();
    values
        .iter()
        .map(|coeff| generator.mul(coeff))
        .collect::<Vec<G>>()
}

/// ******************
/// (De)/Serialization
/// ******************

/// returns the byte representation of a point in projective representation
pub fn group_elements_serialize<G: CurveGroup>(element: &G) -> Result<Vec<u8>, String> {
    let mut serialized = Vec::new();
    match element.serialize_uncompressed(&mut serialized) {
        Ok(_) => Ok(serialized),
        Err(v) => Err(v.to_string()),
    }
}

/// returns the point from a projective byte representation of a point
pub fn group_elements_deserialize<G: CurveGroup>(value: &[u8]) -> Result<G, String> {
    match G::deserialize_uncompressed_unchecked(value) {
        Ok(val) => Ok(val),
        Err(err) => Err(err.to_string()),
    }
}

/// returns the point from an affine byte representation of a point
pub fn group_elements_deserialize_and_validate<G: CurveGroup>(
    value: &[u8],
) -> Result<G::Affine, String> {
    match G::Affine::deserialize_uncompressed_unchecked(value) {
        Ok(val) => Ok(val),
        Err(err) => Err(err.to_string()),
    }
}
