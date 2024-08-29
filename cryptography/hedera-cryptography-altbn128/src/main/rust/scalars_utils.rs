use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_std::UniformRand;
use rand::Rng;

/// Generic utility functions to instantiate scalars (fr)
/// In summary:
/// Fq defines the coordinate field for the points on the curve (where the curve is drawn).
/// Fr defines the field for the scalars used in operations on the curve, typically corresponding to the prime order of a subgroup of points on the curve.

pub type F = ark_bn254::Fr;

/// creates a scalar from an u8 array reference
/// G is a curve group
pub fn scalars_from_bytes(value: &[u8]) -> F {
    F::from_le_bytes_mod_order(&value)
}

/// creates an u8 vector out of a scalar
/// G is a curve group
pub fn scalars_to_bytes(value: F) -> Vec<u8> {
    value.into_bigint().to_bytes_le()
}

/// creates a 0 scalar value
/// G is a curve group
pub fn scalars_zero() -> F {
    F::zero()
}

/// creates a 1 scalar value
/// G is a curve group
pub fn scalars_one() -> F {
    F::one()
}

/// creates a scalar from an initialized random number generator
/// G is a curve group
pub fn scalars_from_random<R: Rng>(rng: &mut R) -> F {
    F::rand(rng)
}

/// creates a scalar from an u64
/// G is a curve group
pub fn scalars_from_u64(value: u64) -> F {
    F::from(value)
}
