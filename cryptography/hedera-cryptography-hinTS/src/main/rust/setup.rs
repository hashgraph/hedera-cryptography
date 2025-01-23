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

/// module responsible for generating the CRS
/// implements the algorithm in https://eprint.iacr.org/2022/1592.pdf
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::*, UniformRand};
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use sha2::*;

use crate::check_or_return_false;
use crate::hints::{Curve, G1AffinePoint, G2AffinePoint, CRS, F};
use crate::kzg;

/// standard Schnorr proof of knowledge
#[derive(CanonicalDeserialize, CanonicalSerialize, PartialEq, Debug)]
pub struct ContributionProof {
    p1_mul_z: G1AffinePoint,
    z_plus_hr: F,
}

pub struct PowersOfTauProtocol {}

impl PowersOfTauProtocol {
    /// outputs the initial CRS without any entropy, to kickstart the ceremony;
    /// this should be the first CRS without any participant's contribution;
    /// don't use this CRS!!! Wait till you have enough participants.
    /// Observe that this is equivalent to CRS with \tau = 1.
    pub fn init(degree: usize) -> CRS {
        kzg::UniversalParams {
            powers_of_g: vec![G1AffinePoint::generator(); degree + 1],
            powers_of_h: vec![G2AffinePoint::generator(); degree + 1],
        }
    }

    /// contributes to the CRS ceremony by adding key material to the existing CRS;
    /// the participant's material is derived from a random scalar r.
    /// returns the updated CRS and the proof of validity of the contribution.
    pub fn contribute(crs: &CRS, seed: [u8; 32]) -> (CRS, ContributionProof) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
        let r = F::rand(&mut rng);

        let degree = crs.powers_of_g.len() - 1;

        let powers_of_r = (0..=degree).map(|i| r.pow(&[i as u64])).collect::<Vec<F>>();

        // zip powers of g with powers of r
        let powers_of_g = crs
            .powers_of_g
            .iter()
            .zip(powers_of_r.iter())
            .map(|(g_i, r_i)| g_i.mul(r_i).into_affine())
            .collect::<Vec<G1AffinePoint>>();

        // zip powers of h with powers of r
        let powers_of_h = crs
            .powers_of_h
            .iter()
            .zip(powers_of_r.iter())
            .map(|(h_i, r_i)| h_i.mul(r_i).into_affine())
            .collect::<Vec<G2AffinePoint>>();

        let next_crs: CRS = kzg::UniversalParams {
            powers_of_g,
            powers_of_h,
        };

        let proof = schnorr_nizk(
            &crs.powers_of_g[1],
            &next_crs.powers_of_g[1],
            &r,
            &mut rng,
        );

        (next_crs, proof)
    }

    /// verifies that the update to the CRS is valid using the proof of contribution
    pub fn verify_contribution(prev_crs: &CRS, next_crs: &CRS, proof: &ContributionProof) -> bool {
        check_or_return_false!(check1(
            &prev_crs.powers_of_g[1],
            &next_crs.powers_of_g[1],
            proof
        ));
        check_or_return_false!(check2(next_crs));
        check_or_return_false!(check3(next_crs));

        true
    }
}

/// Schnorr prover for knowledge of discrete logarithm of next_p1 w.r.t. prev_p1
fn schnorr_nizk<R: Rng>(
    prev_p1: &G1AffinePoint,
    next_p1: &G1AffinePoint,
    r: &F,
    rng: &mut R,
) -> ContributionProof {
    let z = F::rand(rng);
    let prev_p1_mul_z = prev_p1.mul(&z).into_affine();
    let h = random_oracle(prev_p1, next_p1, &prev_p1_mul_z);
    let z_plus_hr = z + h * r;

    ContributionProof {
        p1_mul_z: prev_p1_mul_z,
        z_plus_hr,
    }
}

/// verify the Schnorr proof of knowledge of discrete logarithm of next_p1 w.r.t. prev_p1
fn check1(prev_p1: &G1AffinePoint, next_p1: &G1AffinePoint, proof: &ContributionProof) -> bool {
    let h = random_oracle(prev_p1, next_p1, &proof.p1_mul_z);
    let lhs = prev_p1.mul(&proof.z_plus_hr).into_affine();
    let rhs = proof.p1_mul_z.add(next_p1.mul(h)).into_affine();
    lhs == rhs
}

// random oracle used for the Fiat-Shamir transformation of Schnorr proof
fn random_oracle(
    prev_p1: &G1AffinePoint,
    next_p1: &G1AffinePoint,
    prev_p1_mul_z: &G1AffinePoint,
) -> F {
    let mut prev_p1_bytes = Vec::new();
    prev_p1.serialize_uncompressed(&mut prev_p1_bytes).unwrap();

    let mut next_p1_bytes = Vec::new();
    next_p1.serialize_uncompressed(&mut next_p1_bytes).unwrap();

    let mut prev_p1_mul_z_bytes = Vec::new();
    prev_p1_mul_z
        .serialize_uncompressed(&mut prev_p1_mul_z_bytes)
        .unwrap();

    F::from_le_bytes_mod_order(&compute_sha256(&[
        next_p1_bytes.as_slice(),
        prev_p1_bytes.as_slice(),
        prev_p1_mul_z_bytes.as_slice(),
    ]))
}

// checks well-formedness using pairing equations
fn _check2_unoptimized(crs: &CRS) -> bool {
    let n = crs.powers_of_g.len() - 1;

    for i in 0..n {
        let lhs = <Curve as Pairing>::pairing(crs.powers_of_g[i], crs.powers_of_h[i + 1]);
        let rhs = <Curve as Pairing>::pairing(crs.powers_of_g[i + 1], crs.powers_of_h[i]);

        if lhs != rhs {
            return false;
        }
    }

    return true;
}

// eqn 4.3 in https://eprint.iacr.org/2022/1592.pdf
fn check2(crs: &CRS) -> bool {
    let n = crs.powers_of_g.len() - 1;

    let mut crs_bytes = Vec::new();
    crs.serialize_uncompressed(&mut crs_bytes).unwrap();

    // use random oracle with domain separators
    let rho1 = F::from_le_bytes_mod_order(&compute_sha256(&[crs_bytes.as_slice(), &[1u8]]));
    let rho2 = F::from_le_bytes_mod_order(&compute_sha256(&[crs_bytes.as_slice(), &[2u8]]));

    // c.f. Definition 3 in https://eprint.iacr.org/2022/1592.pdf
    // We say that crs (P1,P2,...,Pn; Q1,Q2,...,Qn) is well-formed
    // if there exists a \tau \in Zp s.t. P_i = \tau^i * B1 and Q_i = \tau^i * B2,
    // where B1 and B2 are the generators of G1 and G2 respectively.
    // NOTE: we store B1 and B2 at index 0 in the powers_of_g and powers_of_h arrays

    let lhs_lhs = <<Curve as Pairing>::G1 as VariableBaseMSM>::msm(
        &crs.powers_of_g[1..=n],
        &(0..=n - 1)
            .map(|i| rho1.pow(&[i as u64]))
            .collect::<Vec<F>>(),
    )
    .unwrap()
    .into_affine();

    let lhs_rhs = <<Curve as Pairing>::G2 as VariableBaseMSM>::msm(
        &crs.powers_of_h[1..=n - 1],
        &(1..=n - 1)
            .map(|i| rho2.pow(&[i as u64]))
            .collect::<Vec<F>>(),
    )
    .unwrap()
    .add(crs.powers_of_h[0])
    .into_affine();

    let rhs_lhs = <<Curve as Pairing>::G1 as VariableBaseMSM>::msm(
        &crs.powers_of_g[1..=n - 1],
        &(1..=n - 1)
            .map(|i| rho1.pow(&[i as u64]))
            .collect::<Vec<F>>(),
    )
    .unwrap()
    .add(crs.powers_of_g[0])
    .into_affine();

    let rhs_rhs = <<Curve as Pairing>::G2 as VariableBaseMSM>::msm(
        &crs.powers_of_h[1..=n],
        &(0..=n - 1)
            .map(|i| rho2.pow(&[i as u64]))
            .collect::<Vec<F>>(),
    )
    .unwrap()
    .into_affine();

    let lhs = <Curve as Pairing>::pairing(lhs_lhs, lhs_rhs);
    let rhs = <Curve as Pairing>::pairing(rhs_lhs, rhs_rhs);

    lhs == rhs
}

// eqn 4.4 in https://eprint.iacr.org/2022/1592.pdf
fn check3(crs: &CRS) -> bool {
    // note that we use location 0 to store the generator (denoted B1)
    // so we need to perform this check for element at index 1
    return crs.powers_of_g[1] != G1AffinePoint::zero();
}

// takes a list of byte slices and computes the sha256 hash
// warning: this can lead to collisions if used unproperly.
// this is just meant for use within check2
pub fn compute_sha256(inputs: &[impl AsRef<[u8]>]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    // just concatenate all the byte slices
    for input in inputs {
        hasher.update(input.as_ref());
    }
    hasher.finalize().into()
}

#[allow(unused_imports)]
mod tests {
    use super::{PowersOfTauProtocol as Prot, *};

    #[test]
    fn test_powers_of_tau_protocol() {
        let degree = 32;
        let crs = Prot::init(degree);

        // WARN: don't use a fixed seed in production
        let (next_crs, proof) = Prot::contribute(&crs, [0u8; 32]);
        assert!(Prot::verify_contribution(&crs, &next_crs, &proof));

        // WARN: don't use a fixed seed in production
        let (next_next_crs, proof) = Prot::contribute(&next_crs, [1u8; 32]);
        assert!(Prot::verify_contribution(&next_crs, &next_next_crs, &proof));

        // serialization test
        assert_eq!(
            next_next_crs,
            crate::hints::deserialize::<CRS>(&crate::hints::serialize(&next_next_crs))
        );
    }
}
