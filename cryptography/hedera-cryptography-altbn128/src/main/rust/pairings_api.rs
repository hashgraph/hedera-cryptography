use std::ops::{Add, Mul};
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::Polynomial;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;

pub type Id = u64;

/// the id this node will use for identifying shares
pub type GroupElement<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;
type FieldElement = ark_bn254::Fr;

/// group element encoding the BLS public key
pub type BlsPublicKey<G> = <G as CurveGroup>::Affine;



pub fn field_elements_operations<R: Rng>(){
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
    (1..=12).map(FieldElement::from).collect::<Vec<FieldElement>>();
    FieldElement::rand(&mut rng);
    FieldElement::zero();
    FieldElement::rand(&mut rng) +  FieldElement::rand(&mut rng) *  FieldElement::rand(&mut rng);
    FieldElement::one();

    let xs: &[FieldElement] = &[];
    let i: usize =10;
    let x: FieldElement = FieldElement::rand(&mut rng);
    let xi = xs[i];
    let mut numerator = FieldElement::one();
    let mut denominator = FieldElement::one();
    for (j, xj) in xs.iter().enumerate() {
        if i != j {
            numerator *= x - xj;
            denominator *= xi - xj;
        }
    }
    numerator * denominator.inverse().unwrap();

    FieldElement::one().into_bigint();
    FieldElement::one() + FieldElement::one() * x.pow(FieldElement::one().into_bigint());
}

pub fn field_elements_operations2<G: CurveGroup, R: Rng>( rng: &mut R)  {
    GroupElement::<G>::zero();
    GroupElement::<G>::one();
    GroupElement::<G>::one().clone();
    GroupElement::<G>::zero() + GroupElement::<G>::one();
    GroupElement::<G>::from(10 as u64);
    GroupElement::<G>::from(10 as u64).pow([10 as u64]);
    GroupElement::<G>::rand(rng);
    // *shares.iter().max().unwrap_or(&ShareId::<G>::zero()) + ShareId::<G>::one();
    let rs = (0..32).map(|_| G::ScalarField::rand(rng)).collect::<Vec<G::ScalarField>>();
    let shared_randomness = (0..32).map(|_| G::ScalarField::rand(rng)).collect::<Vec<G::ScalarField>>();
    let combined_randombess = shared_randomness
        .iter()
        .enumerate()
        .fold(
            G::ScalarField::zero(),
            |acc, (i, &r)| acc + r * G::ScalarField::from(256u64).pow([i as u64])
        );
    GroupElement::<G>::from(10 as u64) * G::ScalarField::from(256u64).pow([10 as u64]);
    G::ScalarField::rand(rng);
    G::ScalarField::zero() -   G::ScalarField::rand(rng);
    let mut msg = G::ScalarField::zero();
    msg += G::ScalarField::from(256u64).pow([10 as u64]) * G::ScalarField::rand(rng);
    G::ScalarField::rand(rng);
    let mut serialized_msg = Vec::new();
    msg.serialize_compressed(&mut serialized_msg).unwrap();
    msg.serialize_uncompressed(&mut serialized_msg).unwrap();

    G::ScalarField::rand(rng);
    let z_r = G::ScalarField::rand(rng) * G::ScalarField::rand(rng) + G::ScalarField::rand(rng);

}

pub fn group_operations<G: CurveGroup, R: Rng>( rng: &mut R)  {
    G::zero() + G::zero().mul(G::ScalarField::rand(rng));
    G::zero() + G::zero();
    Vec::new().iter().fold(G::zero(), |acc, y_i| { acc + y_i });
    G::zero().into_affine();
    G::generator();
    G::generator().mul(&G::ScalarField::rand(rng)).into_affine();
    G::Affine::zero();

    G::Affine::zero().add(G::Affine::zero().mul(&G::ScalarField::rand(rng).pow(G::ScalarField::rand(rng).into_bigint())).into_affine()).into_affine();
    let Y = G::Affine::zero().mul(G::ScalarField::rand(rng)).add(G::Affine::zero()).into_affine();
    G::Affine::zero().mul(&G::ScalarField::rand(&rng)).add(&G::Affine::zero()).into_affine();
    let rhs = G::generator().mul(&G::ScalarField::rand(&rng)).into_affine();
    G::Affine::zero().add(G::Affine::zero().mul(G::ScalarField::rand(rng).pow(G::ScalarField::rand(rng).into_bigint())).into_affine()).into_affine();
    G::Affine::zero().clone();
}

pub fn polinomial<G: CurveGroup, R: Rng>(secret: FieldElement, threshold: usize ){
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
    let mut coefficients = vec![secret]; // the secret is embedded at x = 0
    (1..threshold).for_each(|_| coefficients.push(FieldElement::rand(&mut rng)));

    let polynomial = DensePolynomial { coeffs: {
        coefficients
    }};
    let vec: Vec<G::ScalarField>::new();
    vec.iter().map(|x| polynomial.evaluate(x)).collect::<Vec<FieldElement>>();

}