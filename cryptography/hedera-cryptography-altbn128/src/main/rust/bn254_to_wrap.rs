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

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand_chacha::rand_core::SeedableRng;
use std::ops::Mul;

/// scalars (fr), field elements (fq) and elliptic curve points (Group Elements).

///Fr vs Fq
/// To explain the difference between Fr and Fq in simpler terms:
/// * Fq (Base Field): This is the field over which the curve is defined. The points on the curve have coordinates that are elements of this field.
/// i.e., the x and y coordinates of the points on the elliptic curve are elements of Fq.
/// * Fr (Scalar Field): This is the field over which scalars (the numbers used in elliptic curve operations like point multiplication) are defined. The scalars are elements of Fr.
/// This field is related to the order of the group of points on the curve, which is a prime number r. Scalar multiplications happen in this field.
/// In summary:
/// Fq defines the coordinate field for the points on the curve (where the curve is drawn).
/// Fr defines the field for the scalars used in operations on the curve, typically corresponding to the prime order of a subgroup of points on the curve.

/// the id this node will use for identifying shares
pub type ScalarField<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;

pub fn field_elements_lagrange_coefficient<F: Field>(xs: &[F], i: usize, x: F) -> F {
    let xi = xs[i];
    let mut numerator = F::one();
    let mut denominator = F::one();
    for (j, xj) in xs.iter().enumerate() {
        if i != j {
            numerator *= x - xj;
            denominator *= xi - xj;
        }
    }
    numerator * denominator.inverse().unwrap()
}

pub fn field_elements_zero<F: PrimeField>() -> F {
    F::zero()
}

pub fn field_elements_one<F: PrimeField>() -> F {
    F::one()
}

pub fn field_elements_multiply<F: PrimeField>(value: F, value2: F) -> F {
    value * value2
}

pub fn field_elements_add<F: PrimeField>(value: F, value2: F) -> F {
    value + value2
}

pub fn field_elements_subtract<F: PrimeField>(value: F, value2: F) -> F {
    value - value2
}

pub fn field_elements_from_random<F: PrimeField>(seed: [u8; 32]) -> F {
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
    F::rand(&mut rng)
}

pub fn field_elements_from_long<F: PrimeField>(value: u64) -> F {
    F::from(value)
}

pub fn field_elements_serialize<F: PrimeField>(value: F) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}

pub fn field_elements_deserialize<F: PrimeField>(value: Vec<u8>) -> F {
    F::from_le_bytes_mod_order(&value)
}

pub fn scalars_deserialize<G: CurveGroup>(value: &[u8]) -> ScalarField<G> {
    ScalarField::<G>::from_le_bytes_mod_order(&value)
}

pub fn scalars_zero<G: CurveGroup>() -> ScalarField<G> {
    ScalarField::<G>::zero()
}

pub fn scalars_one<G: CurveGroup>() -> ScalarField<G> {
    ScalarField::<G>::one()
}

pub fn scalars_add<G: CurveGroup>(value: ScalarField<G>, value2: ScalarField<G>) -> ScalarField<G> {
    value + value2
}

pub fn scalars_from_random<G: CurveGroup>() -> ScalarField<G> {
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
    ScalarField::<G>::rand(&mut rng)
}
pub fn scalars_from<G: CurveGroup>(value: u128) -> ScalarField<G> {
    ScalarField::<G>::from(value)
}

pub fn scalars_add<G: CurveGroup>(value: ScalarField<G>, value2: ScalarField<G>) -> ScalarField<G> {
    value + value2
}

pub fn scalars_inverse<G: CurveGroup>(value: ScalarField<G>) -> ScalarField<G> {
    value.inverse().unwrap()
}

pub fn scalars_to_big_int<G: CurveGroup>(value: ScalarField<G>) -> Vec<u64> {
    value.into_bigint().as_ref().to_vec()
}

pub fn scalars_pow<G: CurveGroup>(value: ScalarField<G>, exponent: u64) -> ScalarField<G> {
    value.pow([exponent])
}

pub fn scalars_minus<G: CurveGroup>(
    value: ScalarField<G>,
    value2: ScalarField<G>,
) -> ScalarField<G> {
    value - value2
}

pub fn scalars_multiply<G: CurveGroup>(
    value: ScalarField<G>,
    value2: ScalarField<G>,
) -> ScalarField<G> {
    value * value2
}

pub fn scalars_from_int<G: CurveGroup>(value: u64) -> ScalarField<G> {
    ScalarField::<G>::from(value)
}

pub fn scalars_multiple_from_random<G: CurveGroup>() -> Vec<ScalarField<G>> {
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
    (0..32)
        .map(|_| ScalarField::<G>::rand(&mut rng))
        .collect::<Vec<ScalarField<G>>>()
}

pub fn scalars_max<G: CurveGroup>(value: Vec<ScalarField<G>>) -> ScalarField<G> {
    *value.iter().max().unwrap_or(&ScalarField::<G>::zero())
}

///
/// accumulation done in the context of sss where values are (0..32).map(|_| G::ScalarField::rand(rng)).collect::<Vec<G::ScalarField>>();
pub fn scalars_accum<G: CurveGroup>(values: Vec<ScalarField<G>>) -> ScalarField<G> {
    values
        .iter()
        .enumerate()
        .fold(ScalarField::<G>::zero(), |acc, (i, &r)| {
            acc + r * ScalarField::<G>::from(256u64).pow([i as u64])
        })
}

pub fn scalars_serialize_compressed<G: CurveGroup>(value: ScalarField<G>) -> Vec<u8> {
    let mut serialized_msg = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    serialized_msg
}

pub fn scalars_serialize_uncompressed<G: CurveGroup>(value: ScalarField<G>) -> Vec<u8> {
    let mut serialized_msg = Vec::new();
    value.serialize_uncompressed(&mut serialized_msg).unwrap();
    serialized_msg
}

pub fn scalars_acum<G: CurveGroup>(value: Vec<ScalarField<G>>) -> ScalarField<G> {
    *value.iter().max().unwrap_or(&ScalarField::<G>::zero())
}

pub fn group_elements_equality<G: CurveGroup>(value: G, value2: G) -> bool {
    value.into_affine() == value2.into_affine()
}

pub fn group_elements_zero<G: CurveGroup>() -> G {
    G::zero()
}

pub fn group_elements_generator<G: CurveGroup>() -> G {
    G::generator()
}

pub fn group_elements_to_affine<G: CurveGroup>(element: G) -> G::Affine {
    element.into_affine()
}

pub fn group_elements_add<G: CurveGroup>(value: G, value2: G) -> G {
    value + value2
}

pub fn group_elements_add_affine<G: CurveGroup>(value: G, value2: G) -> G::Affine {
    (value.into_affine() + value2.into_affine()).into()
}

pub fn group_elements_scalar_multiply<G: CurveGroup>(
    value: G,
    value2: ScalarField<G>,
) -> G::Affine {
    value.into_affine().mul(value2).into_affine()
}

pub fn group_elements_acum<G: CurveGroup>(values: Vec<G>) -> G {
    values.iter().fold(G::zero(), |acc, point| acc + point)
}

pub fn group_elements_serialize<G: CurveGroup>(element: &G::Affine) -> Vec<u8> {
    let mut serialized = Vec::new();
    element.serialize_uncompressed(&mut serialized).unwrap();
    serialized
}

pub fn group_elements_g1_xy(a: G1Affine) -> (BigInt<4>, BigInt<4>) {
    (a.x().unwrap().into_bigint(), a.y().unwrap().into_bigint())
}

pub fn group_elements_g1_from_xy(x: BigInt<4>, y: BigInt<4>) -> G1Affine {
    // Finally, while not recommended,
    // users can directly construct group elements
    // from the x and y coordinates. This is useful when implementing algorithms
    // like hash-to-curve.
    let x_fq = Fq::new(x);
    let y_fq = Fq::new(y);
    G1Affine::new(x_fq, y_fq)
}

pub fn group_elements_g2_xy(a: G2Affine) -> (BigInt<4>, BigInt<4>, BigInt<4>, BigInt<4>) {
    (
        a.x().unwrap().c0.into_bigint(),
        a.x().unwrap().c1.into_bigint(),
        a.y().unwrap().c0.into_bigint(),
        a.y().unwrap().c1.into_bigint(),
    )
}

pub fn group_elements_g2_from_xy(
    x1: BigInt<4>,
    x2: BigInt<4>,
    y1: BigInt<4>,
    y2: BigInt<4>,
) -> G2Affine {
    // FROM: https://docs.rs/ark-algebra-intro/latest/ark_algebra_intro/
    // Finally, while not recommended, users can directly construct group elements
    // from the x and y coordinates. This is useful when implementing algorithms
    // like hash-to-curve.
    let x_fq2 = Fq2::new(Fq::new(x1), Fq::new(x2));
    let y_fq2 = Fq2::new(Fq::new(y1), Fq::new(y2));
    G2Affine::new(x_fq2, y_fq2)
}

pub fn group_elements_batch_multiply<G: CurveGroup>(values: Vec<ScalarField<G>>) -> Vec<G::Affine> {
    let generator = G::generator();
    values
        .iter()
        .map(|coeff| generator.into_affine().mul(coeff).into_affine())
        .collect::<Vec<G::Affine>>()
}

pub fn pairings_is_equal<G: CurveGroup>(
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
    d: G2Affine,
) -> bool {
    let p1 = Bn254::pairing(a, b);
    let p2 = Bn254::pairing(c, d);
    p1 == p2
}

/// taken from: https://docs.rs/fastcrypto/latest/src/fastcrypto/secp256r1/conversion.rs.html
///
/// Reduce a big-endian integer representation modulo the subgroup order in arkworks representation.
pub fn reduce_bytes<F: Field>(bytes: &[u8; 32]) -> ark_bn254::Fr {
    ark_bn254::Fr::from_be_bytes_mod_order(bytes)
}

/// Reduce an arkworks field element (modulo field size) to a scalar (modulo subgroup order). This also
/// returns a boolean indicating whether a modular reduction was performed.
pub fn arkworks_fq_to_fr(scalar: &Fq) -> (ark_bn254::Fr, bool) {
    let mut bytes = [0u8; 32];
    scalar.serialize_uncompressed(&mut bytes[..]).unwrap();
    let output = ark_bn254::Fr::from_le_bytes_mod_order(&bytes);
    (output, output.into_bigint() != scalar.into_bigint())
}

/// Convert coordinates to an arkworks affine G1 point.
pub fn group_elements_g1_from_xy_bytes(x: &[u8], y: &[u8]) -> ark_bn254::G1Projective {
    ark_bn254::G1Projective::from(G1Affine::new_unchecked(
        //if the coordinates are trusted
        Fq::from_be_bytes_mod_order(&x),
        Fq::from_be_bytes_mod_order(y),
    ))
}
