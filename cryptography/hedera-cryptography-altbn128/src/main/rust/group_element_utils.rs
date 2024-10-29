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

use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{Field, PrimeField};
use jni::JNIEnv;
use jni::objects::JByteArray;
use jni::sys::jint;
use crate::jni_helpers;

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

pub fn canonical_serialize<S: CanonicalSerialize>(element: &S) -> Result<Vec<u8>, String> {
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

/// Converts a u8 array into the BaseField representation of the group (the field where the coordinates are represented) if there is such representation
pub fn coordinate_from_hash<G: SWCurveConfig>( candidate: &[u8])->Option<G::BaseField>{
    if G::BaseField::extension_degree() == 1 {
        // if the order is 1 the op is simpler
        let f = <G::BaseField as Field>::BasePrimeField::from_be_bytes_mod_order(
            &candidate,
        );
        G::BaseField::from_base_prime_field_elems(&[f])
    } else {
        G::BaseField::from_random_bytes(&candidate)
    }
}

/// returns the point from an x coordinate if the point is in the curve
pub fn point_from_x<CC: SWCurveConfig>(x: CC::BaseField) -> Option<Affine<CC>> {
    if let Some(p) = Affine::<CC>::get_point_from_x_unchecked(x, false){
        let scaled = p.mul_by_cofactor();
        if scaled.is_zero() {
            return None;
        }
        Some(scaled)
    }else { None }
}

/// returns the point from a hash if the point is in the curve
pub fn elements_from_hash_generic<CC: SWCurveConfig>(
    env: JNIEnv,
    hash_array: &[u8],
    output: JByteArray,
) -> jint {
    let x_option = x_coordinate_from_hash::<CC>(&hash_array);
    if x_option.is_none() {
        return jni_helpers::BUSINESS_ERROR_POINT_NOT_IN_CURVE;
    }
    let point_option = point_from_x::<CC>(x_option.unwrap());
       if point_option.is_none() {
           return jni_helpers::BUSINESS_ERROR_POINT_NOT_IN_CURVE;
       }
    jni_helpers::serialize_to_jbytearray::<Affine<CC>>(env, &point_option.unwrap(), output).unwrap_or_else(|value| value)
}