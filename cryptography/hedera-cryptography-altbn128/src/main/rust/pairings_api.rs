use std::ops::{Add, Mul};
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand_chacha::rand_core::SeedableRng;

pub type Id = u64;

/// the id this node will use for identifying shares
pub type GenFieldElement<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;


pub fn field_elements_lagrange_coefficient<G:CurveGroup>(xs: &[GenFieldElement<G>], i: usize, x: GenFieldElement<G>) -> GenFieldElement<G> {
    let xi = xs[i];
    let mut numerator = GenFieldElement::<G>::one();
    let mut denominator = GenFieldElement::<G>::one();
    for (j, xj) in xs.iter().enumerate() {
        if i != j {
            numerator *= x - xj;
            denominator *= xi - xj;
        }
    }
    numerator * denominator.inverse().unwrap()
}


pub fn field_elements_zero<G:CurveGroup>() -> GenFieldElement<G> {
    GenFieldElement::<G>::zero()
}
pub fn field_elements_one<G:CurveGroup>() -> GenFieldElement<G> {
    GenFieldElement::<G>::one()
}

pub fn field_elements_add<G: CurveGroup>(value: GenFieldElement<G>, value2: GenFieldElement<G>) -> GenFieldElement<G>{
    value + value2
}

pub fn field_elements_from_random<G: CurveGroup>() -> GenFieldElement<G>{
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
    GenFieldElement::<G>::from(&mut rng)
}

pub fn field_elements_inverse<G: CurveGroup>(value: GenFieldElement<G>) -> GenFieldElement<G> {
    value.inverse().unwrap()
}

pub fn field_elements_to_big_int<G: CurveGroup>(value: GenFieldElement<G>)-> BigInt<4> {
    value.into_bigint()
}

pub fn field_elements_pow<G: CurveGroup>(value: GenFieldElement<G>, exponent : u64) -> GenFieldElement<G>{
    value.pow(exponent)
}

pub fn field_elements_minus<G: CurveGroup>(value: GenFieldElement<G>, value2: GenFieldElement<G>) -> GenFieldElement<G>{
    value - value2
}

pub fn field_elements_multiply<G: CurveGroup>(value: GenFieldElement<G>, value2: GenFieldElement<G>) -> GenFieldElement<G>{
    value * value2
}

pub fn field_elements_from_int<G: CurveGroup>(value: u64) -> GenFieldElement<G>{
    GenFieldElement::<G>::from(value)
}


pub fn field_elements_multiple_from_random<G: CurveGroup>() -> Vec<G::GroupElement>{
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
    (0..32).map(|_| G::GroupElement::rand(&mut rng)).collect::<Vec<G::GroupElement>>()
}

pub fn field_elements_max<G: CurveGroup>(value: Vec<G::GroupElement>) -> GenFieldElement<G>{
    value.iter().max().unwrap_or(&GenFieldElement::<G>::zero())
}

pub fn field_elements_accum<G: CurveGroup>(value: Vec<G::GroupElement>) -> GenFieldElement<G>{
    value.iter()
        .enumerate()
        .fold(
            G::GroupElement::zero(),
            |acc, (i, &r)| acc + r * G::GroupElement::from(256u64).pow([i as u64])
        );
}

pub fn field_elements_serialize_compressed<G: CurveGroup>(value: GenFieldElement<G>) -> Vec<u8> {
    let mut serialized_msg = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    serialized_msg
}

pub fn field_elements_serialize_uncompressed<G: CurveGroup>(value: GenFieldElement<G>) -> Vec<u8> {
    let mut serialized_msg = Vec::new();
    value.serialize_uncompressed(&mut serialized_msg).unwrap();
    serialized_msg
}

pub fn field_elements_acum<G: CurveGroup>(value: Vec<G::GenFieldElement>) -> GenFieldElement<G>{
    value.iter().max().unwrap_or(&GenFieldElement::<G>::zero())
}

pub fn group_elements_zero<G: CurveGroup>() -> G{
    G::zero()
}

pub fn group_elements_one<G: CurveGroup>() -> G{
    G::one()
}

pub fn  group_elements_generator<G: CurveGroup>() -> G{
    G::generator()
}

pub fn  group_elements_to_affine<G:CurveGroup>(element:G)->G::Affine{
    element.into_affine()
}

pub fn  group_elements_add<G:CurveGroup>(value:G, value2:G)->G{
    value + value2
}

pub fn  group_elements_add_affine<G:CurveGroup>(value:G, value2:G)->G::Affine{
    value.into_affine() + value2.into_affine()
}

pub fn  group_elements_scalar_multiply<G:CurveGroup>(value:G, value2:GenFieldElement<G>) ->G::Affine{
    value.into_affine().mul( value2).into_affine()
}

pub fn  group_elements_acum<G:CurveGroup>(values:Vec<G>) ->G{
    values.iter().fold(G::zero(), |acc, point| { acc + point });
}

pub fn group_elements_serialize<G: CurveGroup>(element: &G::Affine) -> Vec<u8> {
    let mut serialized = Vec::new();
    element.serialize_uncompressed(&mut serialized).unwrap();
    serialized
}

pub fn group_elements_g1_xy(a:G1Affine) -> (BigInt<4>, BigInt<4>) {
    (a.x().unwrap().0 , a.y().unwrap().0)
}

pub fn group_elements_from_g1_xy(x: BigInt<4>, y: BigInt<4>) ->G1Affine{
    // Finally, while not recommended, users can directly construct group elements
    // from the x and y coordinates. This is useful when implementing algorithms
    // like hash-to-curve.
    let x_fq = Fq::new(x);
    let y_fq =Fq::new(y);
    G1Affine::new(x_fq, y_fq)
}

pub fn group_elements_from_g2_xy(x1: BigInt<4>, x2: BigInt<4>, y1: BigInt<4>, y2: BigInt<4>) ->G2Affine{
    // Finally, while not recommended, users can directly construct group elements
    // from the x and y coordinates. This is useful when implementing algorithms
    // like hash-to-curve.
    let x_fq2 = Fq2::new(Fq::new(x1), Fq::new(x2));
    let y_fq2 =Fq2::new(Fq::new(y1), Fq::new(y2));
    G2Affine::new(x_fq2, y_fq2)
}

pub fn pairings_is_equal<G:CurveGroup>(a: G1Affine, b:G2Affine, c: G1Affine, d:G2Affine ) -> bool {
    let p1 = Bn254::pairing(a, b);
    let p2 = Bn254::pairing(c, d);
   p1 == p2
}

pub fn group_elements_batch_multiply<G: CurveGroup>(values:Vec<&[GenFieldElement<G>]>) -> Vec<G::Affine> {
    let generator = G::generator();
    values
        .iter()
        .map(|coeff| { generator.mul(coeff).into_affine() })
        .collect::<Vec<G::Affine>>()
}

