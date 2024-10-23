use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{Field, PrimeField};

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

pub fn x_coordinate_from_hash<G: CurveGroup>( candidate_hash: &[u8])->Option<G::BaseField>{
    if G::BaseField::extension_degree() == 1 {
        // if the order is 1 the op is simpler
        let f = <G::BaseField as Field>::BasePrimeField::from_be_bytes_mod_order(
            &candidate_hash,
        );
        G::BaseField::from_base_prime_field_elems(&[f])
    } else {
        G::BaseField::from_random_bytes(&candidate_hash)
    }
}

pub fn point_from_x<CC: SWCurveConfig>(x: CC::BaseField) -> Option<Affine<CC>> {
    if let Some(p) = Affine::<CC>::get_point_from_x_unchecked(x, false){
        let scaled = p.mul_by_cofactor();
        if scaled.is_zero() {
            return None;
        }
        Some(scaled)
    }else { None }
}