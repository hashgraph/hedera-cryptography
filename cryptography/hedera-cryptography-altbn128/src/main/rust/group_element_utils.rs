use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ff::{BigInt, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

pub fn group_elements_hash_to_curve<G: CurveGroup>(values: Vec<u8>) -> G {
    G::hash(&values)
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

/// returns the byte representation of a point in affine representation
pub fn group_elements_serialize_affine<G: CurveGroup>(
    element: &G::Affine,
) -> Result<Vec<u8>, String> {
    let mut serialized = Vec::new();
    match element.serialize_uncompressed(&mut serialized) {
        Ok(_) => Ok(serialized),
        Err(v) => Err(v.to_string()),
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

/// ****************
/// Representations
/// ****************

/// returns the point in affine representation from a projective representation of the point
pub fn group_elements_to_affine<G: CurveGroup>(element: G) -> G::Affine {
    element.into_affine()
}
/// returns the point in projective representation from an affine  representation of the point
pub fn group_elements_to_projective<G: CurveGroup>(element: G::Affine) -> G {
    element.into_group()
}

/// extracts x and y coordinates for a G1Affine point
pub fn group_elements_g1_xy(a: G1Affine) -> ([u64; 4], [u64; 4]) {
    (
        a.x().unwrap().into_bigint().0,
        a.y().unwrap().into_bigint().0,
    )
}

/// creates an affine representation of the G1Affine point from x and y coordinates. The point would need to be validated.
/// The 0 point is not supported
pub fn group_elements_g1_from_xy(x: [u64; 4], y: [u64; 4]) -> G1Affine {
    // Finally, while not recommended,
    // users can directly construct group elements
    // from the x and y coordinates. This is useful when implementing algorithms
    // like hash-to-curve.
    let x_fq = Fq::new(BigInt::new(x));
    let y_fq = Fq::new(BigInt::new(y));
    G1Affine::new(x_fq, y_fq)
}

/// extracts x,x and y,y coordinates for a G2Affine point
pub fn group_elements_g2_xy(a: G2Affine) -> ([u64; 4], [u64; 4], [u64; 4], [u64; 4]) {
    (
        a.x().unwrap().c0.into_bigint().0,
        a.x().unwrap().c1.into_bigint().0,
        a.y().unwrap().c0.into_bigint().0,
        a.y().unwrap().c1.into_bigint().0,
    )
}

/// creates an affine representation of the G2Affine point from x,x and y,y coordinates. The point would need to be validated.
/// The 0 point is not supported
pub fn group_elements_g2_from_xy(
    x1: [u64; 4],
    x2: [u64; 4],
    y1: [u64; 4],
    y2: [u64; 4],
) -> G2Affine {
    // FROM: https://docs.rs/ark-algebra-intro/latest/ark_algebra_intro/
    // Finally, while not recommended, users can directly construct group elements
    // from the x and y coordinates. This is useful when implementing algorithms
    // like hash-to-curve.
    let x_fq2 = Fq2::new(Fq::new(BigInt::new(x1)), Fq::new(BigInt::new(x2)));
    let y_fq2 = Fq2::new(Fq::new(BigInt::new(y1)), Fq::new(BigInt::new(y2)));
    G2Affine::new(x_fq2, y_fq2)
}
