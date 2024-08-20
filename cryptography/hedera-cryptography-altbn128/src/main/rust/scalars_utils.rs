use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_std::UniformRand;
use rand::Rng;

/// Generic utility functions to instantiate scalars (fr) or field elements (fq)
/// In summary:
/// Fq defines the coordinate field for the points on the curve (where the curve is drawn).
/// Fr defines the field for the scalars used in operations on the curve, typically corresponding to the prime order of a subgroup of points on the curve.

pub type ScalarField<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;

/// creates a scalar from an u8 array reference
/// G is a curve group
pub fn scalars_from_bytes<G: CurveGroup>(value: &[u8]) -> ScalarField<G> {
    ScalarField::<G>::from_le_bytes_mod_order(&value)
}

/// creates an u8 vector out of a scalar
/// G is a curve group
pub fn scalars_to_bytes<G: CurveGroup>(value: ScalarField<G>) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}

/// creates a 0 scalar value
/// G is a curve group
pub fn scalars_zero<G: CurveGroup>() -> ScalarField<G> {
    ScalarField::<G>::zero()
}

/// creates a 1 scalar value
/// G is a curve group
pub fn scalars_one<G: CurveGroup>() -> ScalarField<G> {
    ScalarField::<G>::one()
}

/// creates a scalar from an initialized random number generator
/// G is a curve group
pub fn scalars_from_random<G: CurveGroup, R: Rng>(rng: &mut R) -> ScalarField<G> {
    ScalarField::<G>::rand(rng)
}

/// creates a scalar from an u64
/// G is a curve group
pub fn scalars_from_u64<G: CurveGroup>(value: u64) -> ScalarField<G> {
    ScalarField::<G>::from(value)
}
