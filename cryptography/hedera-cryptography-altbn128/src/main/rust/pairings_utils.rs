use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;

pub fn pairings_is_equal(
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
    d: G2Affine,
) -> bool {
    let p1 = Bn254::pairing(a, b);
    let p2 = Bn254::pairing(c, d);
    p1 == p2
}