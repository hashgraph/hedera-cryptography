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

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use ark_std::{UniformRand, ops::*};
use ark_bls12_381::{Bls12_381, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, short_weierstrass::{Affine, Projective}};
use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
use ark_ff::{Field, field_hashers::DefaultFieldHasher, BigInteger256};
use sha2::{Digest, Sha256};
use ark_std::collections::HashMap;

// hinTS depends on the utils and kzg modules
use crate::utils;
use crate::kzg;
use crate::{assert_power_of_2, check_or_return_false};

/// Pairing friendly curve powering the hinTS scheme
type Curve = Bls12_381;
/// KZG polynomial commitment scheme
type KZG = kzg::KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
/// Common reference string for the hinTS scheme
type CRS = kzg::UniversalParams<Curve>;
/// Scalar Field
type F = ark_bls12_381::Fr;
/// Represents a point in G1 (affine coordinates)
pub type G1AffinePoint = Affine<G1Config>;
/// Represents a point in G2 (affine coordinates)
pub type G2AffinePoint = Affine<G2Config>;
/// Represents a point in G1 (projective coordinates)
pub type G1ProjectivePoint = Projective<G1Config>;
/// Represents a point in G2 (projective coordinates)
pub type G2ProjectivePoint = Projective<G2Config>;

/// Type denoting a partial signature, which is a G2 group element
pub type PartialSignature = G2AffinePoint;
/// Type denoting secret key, which is just a scalar value
pub type SecretKey = F;
/// Type denoting public key, which is a G1 group element
pub type PublicKey = G1AffinePoint;
/// Type denoting a signer's weight, which is just a scalar value
pub type Weight = F;

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// hinTS aggregate signature
pub struct ThresholdSignature {
    /// aggregate public key (aPK in the paper)
    agg_pk: G1AffinePoint,
    /// aggregate weight (w in the paper)
    agg_weight: Weight,
    /// aggregate signature
    agg_sig: G2AffinePoint,

    /// commitment to the bitmap polynomial ([B(τ)]_1 in the paper)
    b_of_tau_com: G1AffinePoint,
    /// commitment to the Q_x polynomial ([Q_x(τ)]_1 in the paper)
    qx_of_tau_com: G1AffinePoint,
    /// commitment to the Q_x polynomial ([Q_x(τ) . τ ]_1 in the paper)
    qx_of_tau_mul_tau_com: G1AffinePoint,
    /// commitment to the Q_z polynomial ([Q_z(τ)]_1 in the paper)
    qz_of_tau_com: G1AffinePoint,
    /// commitment to the ParSum polynomial ([ParSum(τ)]_1 in the paper)
    parsum_of_tau_com: G1AffinePoint,

    /// commitment to the ParSum well-formedness quotient polynomial
    q1_of_tau_com: G1AffinePoint,
    /// commitment to the ParSum check at omega^{n-1} quotient polynomial
    q3_of_tau_com: G1AffinePoint,
    /// commitment to the bitmap well-formedness quotient polynomial
    q2_of_tau_com: G1AffinePoint,
    /// commitment to the bitmap check at omega^{n-1} quotient polynomial
    q4_of_tau_com: G1AffinePoint,

    /// merged opening proof for all openings at x = r
    opening_proof_r: G1AffinePoint,
    /// proof for the ParSum opening at x = r / ω
    opening_proof_r_div_ω: G1AffinePoint,

    /// polynomial evaluation of ParSum(x) at x = r
    parsum_of_r: F,
    /// polynomial evaluation of ParSum(x) at x = r / ω
    parsum_of_r_div_ω: F,
    /// polynomial evaluation of W(x) at x = r
    w_of_r: F,
    /// polynomial evaluation of bitmap B(x) at x = r
    b_of_r: F,
    /// polynomial evaluation of quotient Q1(x) at x = r
    q1_of_r: F,
    /// polynomial evaluation of quotient Q3(x) at x = r
    q3_of_r: F,
    /// polynomial evaluation of quotient Q2(x) at x = r
    q2_of_r: F,
    /// polynomial evaluation of quotient Q4(x) at x = r
    q4_of_r: F,
}

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// Hint contains all material output by a party during the setup phase
pub struct ExtendedPublicKey {
    /// index in the address book
    i: usize,
    /// universe size (power of 2) for which this extended public key is generated
    n: usize,
    /// public key pk = [sk]_1
    pk_i: PublicKey,
    /// [ sk_i L_i(τ) ]_1
    sk_i_l_i_of_tau_com_1: G1AffinePoint,
    /// [ sk_i L_i(τ) ]_2
    sk_i_l_i_of_tau_com_2: G2AffinePoint,
    /// qz_i_terms[i] = [ sk_i * ((L_i^2(τ) - L_i(τ)) / Z(τ)) ]_1
    /// \forall j != i, qz_i_terms[j] = [ sk_i * (L_i(τ) * L_j(τ) / Z(τ)) ]_1
    qz_i_terms: Vec<G1AffinePoint>,
    /// [ sk_i ((L_i(τ) - L_i(0)) / τ ]_1
    qx_i_term: G1AffinePoint,
    /// [ sk_i ((L_i(τ) - L_i(0))]_1
    qx_i_term_mul_tau: G1AffinePoint,
}

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// AggregationKey contains all material needed by Prover to produce a hinTS proof
pub struct AggregationKey {
    /// number of parties in the universe plus one (must be a power of 2)
    n: usize,
    /// weights has all parties' weights, where weights[i] is party i's weight
    weights: Vec<Weight>,
    /// pks contains all parties' public keys, where pks[i] is g^sk_i
    pks: Vec<PublicKey>,
    /// qz_terms contains pre-processed hints for the Q_z polynomial.
    /// qz_terms[i] has the following form:
    /// [sk_i * (L_i(\tau)^2 - L_i(\tau)) / Z(\tau) + 
    /// \Sigma_{j} sk_j * (L_i(\tau) L_j(\tau)) / Z(\tau)]_1
    qz_terms : Vec<G1AffinePoint>,
    /// qx_terms contains pre-processed hints for the Q_x polynomial.
    /// qx_terms[i] has the form [ sk_i * (L_i(\tau) - L_i(0)) / x ]_1
    qx_terms : Vec<G1AffinePoint>,
    /// qx_mul_tau_terms contains pre-processed hints for the Q_x * x polynomial.
    /// qx_mul_tau_terms[i] has the form [ sk_i * (L_i(\tau) - L_i(0)) ]_1
    qx_mul_tau_terms : Vec<G1AffinePoint>,
}

#[derive(Clone, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
/// structure containing the verification key required to verify a hinTS signature
pub struct VerificationKey {
    /// the universe has n - 1 parties (where n is a power of 2)
    n: usize,
    /// total weight of all signers
    total_weight: Weight,
    /// first G1 element from the KZG CRS (for zeroth power of tau)
    g_0: G1AffinePoint,
    /// first G2 element from the KZG CRS (for zeroth power of tau)
    h_0: G2AffinePoint,
    /// second G1 element from the KZG CRS (for first power of tau)
    h_1: G2AffinePoint,
    /// commitment to the L_{n-1} polynomial
    l_n_minus_1_of_tau_com: G1AffinePoint,
    /// commitment to the W polynomial
    w_of_tau_com: G1AffinePoint,
    /// commitment to the SK polynomial
    sk_of_tau_com: G2AffinePoint,
    /// commitment to the vanishing polynomial Z(x) = x^n - 1
    z_of_tau_com: G2AffinePoint,
    /// commitment to the f(x) = x, which equals [\tau]_2
    tau_com: G2AffinePoint
}

pub struct HinTS;

impl HinTS {

    /// generates a random secret key using the supplied random number generator
    pub fn keygen<R: rand::Rng>(rng: &mut R) -> SecretKey {
        F::rand(rng)
    }

    /// generates the extended public key (a.k.a. hint) for signer with
    /// secret key sk and index i within a universe of n-1 signers 
    pub fn hint_gen(
        crs: &CRS,
        n: usize, 
        i: usize, 
        sk: &SecretKey
    ) -> ExtendedPublicKey {
        assert_power_of_2!(n);

        //let us compute the q1 term
        let l_i_of_x = utils::lagrange_poly(n, i);
        let z_of_x = utils::compute_vanishing_poly(n);
    
        let mut qz_terms = vec![];
        //let us compute the cross terms of q1
        for j in 0..n {
            let num: DensePolynomial<F>;// = compute_constant_poly(&F::from(0));
            if i == j {
                num = l_i_of_x.mul(&l_i_of_x).sub(&l_i_of_x);
            } else { //cross-terms
                let l_j_of_x = utils::lagrange_poly(n, j);
                num = l_j_of_x.mul(&l_i_of_x);
            }
    
            let f = num.div(&z_of_x);
            let sk_times_f = utils::poly_eval_mult_c(&f, &sk);
    
            let com = KZG::commit_g1(&crs, &sk_times_f).unwrap();
    
            qz_terms.push(com);
        }
    
        let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
        let l_i_of_0_poly = utils::compute_constant_poly(&l_i_of_0);
    
        //numerator is l_i(x) - l_i(0)
        let num = l_i_of_x.sub(&l_i_of_0_poly);
        //denominator is x
        let den = utils::compute_x_monomial();
        //qx_term = sk_i * (l_i(x) - l_i(0)) / x
        let qx_term = utils::poly_eval_mult_c(&num.div(&den), &sk);
        //qx_term_mul_tau = sk_i * (l_i(x) - l_i(0)) / x
        let qx_term_mul_tau = utils::poly_eval_mult_c(&num, &sk);
        //qx_term_com = [ sk_i * (l_i(τ) - l_i(0)) / τ ]_1
        let qx_term_com = KZG::commit_g1(&crs, &qx_term).unwrap();
        //qx_term_mul_tau_com = [ sk_i * (l_i(τ) - l_i(0)) ]_1
        let qx_term_mul_tau_com = KZG::commit_g1(&crs, &qx_term_mul_tau).unwrap();
    
        //release my public key
        let sk_as_poly = utils::compute_constant_poly(sk);
        let pk = KZG::commit_g1(&crs, &sk_as_poly).unwrap();
    
        let sk_times_l_i_of_x = utils::poly_eval_mult_c(&l_i_of_x, &sk);
        let com_sk_l_i_g1 = KZG::commit_g1(&crs, &sk_times_l_i_of_x).unwrap();
        let com_sk_l_i_g2 = KZG::commit_g2(&crs, &sk_times_l_i_of_x).unwrap();
    
        ExtendedPublicKey {
            i: i,
            n: n,
            pk_i: pk,
            sk_i_l_i_of_tau_com_1: com_sk_l_i_g1,
            sk_i_l_i_of_tau_com_2: com_sk_l_i_g2,
            qz_i_terms: qz_terms,
            qx_i_term: qx_term_com,
            qx_i_term_mul_tau: qx_term_mul_tau_com,
        }
    }

    /// verifies whether the extended public key is well-formed
    pub fn verify_hint(
        crs: &CRS,
        hint: &ExtendedPublicKey
    ) -> bool {
        let i = hint.i;

        // sanity check on the hint
        assert_eq!(hint.n, hint.qz_i_terms.len());

        //e([sk_i L_i(τ)]1, [1]2) = e([sk_i]1, [L_i(τ)]2)
        let l_i_of_x = utils::lagrange_poly(hint.n, i);
        let z_of_x = utils::compute_vanishing_poly(hint.n);

        let l_i_of_tau_com = KZG::commit_g2(&crs, &l_i_of_x).unwrap();
        let lhs = <Curve as Pairing>::pairing(hint.sk_i_l_i_of_tau_com_1, crs.powers_of_h[0]);
        let rhs = <Curve as Pairing>::pairing(hint.pk_i, l_i_of_tau_com);
        check_or_return_false!(lhs == rhs);

        for j in 0..hint.n {
            let num: DensePolynomial<F>;
            if i == j {
                num = l_i_of_x.clone().mul(&l_i_of_x).sub(&l_i_of_x);
            } else { //cross-terms
                let l_j_of_x = utils::lagrange_poly(hint.n, j);
                num = l_j_of_x.mul(&l_i_of_x);
            }
            let f = num.div(&z_of_x);

            //f = li^2 - l_i / z or li lj / z
            let f_com = KZG::commit_g2(&crs, &f).unwrap();

            let lhs = <Curve as Pairing>::pairing(hint.qz_i_terms[j], crs.powers_of_h[0]);
            let rhs = <Curve as Pairing>::pairing(hint.pk_i, f_com);
            check_or_return_false!(lhs == rhs);
        }

        let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
        let l_i_of_0_poly = utils::compute_constant_poly(&l_i_of_0);

        //numerator is l_i(x) - l_i(0)
        let num = l_i_of_x.sub(&l_i_of_0_poly);
        //denominator is x
        let den = utils::compute_x_monomial();

        //qx_term = (l_i(x) - l_i(0)) / x
        let qx_term = &num.div(&den);
        //qx_term_com = [ sk_i * (l_i(τ) - l_i(0)) / τ ]_1
        let qx_term_com = KZG::commit_g2(&crs, &qx_term).unwrap();
        let lhs = <Curve as Pairing>::pairing(hint.qx_i_term, crs.powers_of_h[0]);
        let rhs = <Curve as Pairing>::pairing(hint.pk_i, qx_term_com);
        check_or_return_false!(lhs == rhs);

        //qx_term_mul_tau = (l_i(x) - l_i(0))
        let qx_term_mul_tau = &num;
        //qx_term_mul_tau_com = [ (l_i(τ) - l_i(0)) ]_1
        let qx_term_mul_tau_com = KZG::commit_g2(&crs, &qx_term_mul_tau).unwrap();
        let lhs = <Curve as Pairing>::pairing(hint.qx_i_term_mul_tau, crs.powers_of_h[0]);
        let rhs = <Curve as Pairing>::pairing(hint.pk_i, qx_term_mul_tau_com);
        check_or_return_false!(lhs == rhs);

        true
    }

    /// preprocesses all signers' extended public keys and weights,
    /// and outputs the network's verification key and aggregation key
    pub fn preprocess(
        n: usize,
        crs: &CRS,
        signer_info: &HashMap<usize, (Weight, ExtendedPublicKey)>,
    ) -> (VerificationKey, AggregationKey) {
        assert_power_of_2!(n);
    
        let mut weights: Vec<Weight> = Vec::new();
        let mut epks: Vec<ExtendedPublicKey> = Vec::new();
        for i in 0..n {
            if let Some((weight, hint)) = signer_info.get(&i) {
                assert!(hint.n == n);
                weights.push(weight.clone());
                epks.push(hint.clone());
            } else {
                weights.push(F::from(0));
                epks.push(Self::hint_gen(crs, n, i, &F::from(0)));
            }
        }


        let w_of_x = utils::interpolate_poly_over_mult_subgroup(&weights);
    
        //allocate space to collect setup material from all n-1 parties
        let mut qz_contributions : Vec<Vec<G1AffinePoint>> = vec![Default::default(); n];
        let mut qx_contributions : Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut qx_mul_tau_contributions : Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut pks : Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut sk_l_of_tau_coms: Vec<G2AffinePoint> = vec![Default::default(); n];
    
        for hint in epks {
            //extract necessary items for pre-processing
            qz_contributions[hint.i] = hint.qz_i_terms.clone();
            qx_contributions[hint.i] = hint.qx_i_term.clone();
            qx_mul_tau_contributions[hint.i] = hint.qx_i_term_mul_tau.clone();
            pks[hint.i] = hint.pk_i.clone();
            sk_l_of_tau_coms[hint.i] = hint.sk_i_l_i_of_tau_com_2.clone();
        }
    
        let z_of_x = utils::compute_vanishing_poly(n);
        let x_monomial = utils::compute_x_monomial();
        let l_n_minus_1_of_x = utils::lagrange_poly(n, n-1);

        let total_weight = weights.iter().fold(F::from(0), |acc, &x| acc + x);
    
        let vk = VerificationKey {
            n: n,
            total_weight: total_weight,
            g_0: crs.powers_of_g[0],
            h_0: crs.powers_of_h[0],
            h_1: crs.powers_of_h[1],
            l_n_minus_1_of_tau_com: KZG::commit_g1(&crs, &l_n_minus_1_of_x).unwrap(),
            w_of_tau_com: KZG::commit_g1(&crs, &w_of_x).unwrap(),
            sk_of_tau_com: add::<G2AffinePoint>(sk_l_of_tau_coms),
            z_of_tau_com: KZG::commit_g2(&crs, &z_of_x).unwrap(),
            tau_com: KZG::commit_g2(&crs, &x_monomial).unwrap(),
        };
    
        let ak = AggregationKey {
            n: n,
            weights: weights,
            pks: pks,
            qz_terms: preprocess_qz_contributions(&qz_contributions),
            qx_terms: qx_contributions,
            qx_mul_tau_terms: qx_mul_tau_contributions,
        };
    
        (vk, ak)
    
    }

    /// signs a message using the signer's secret key, producing a partial signature
    pub fn sign(
        msg: &[u8],
        sk: &SecretKey
    ) -> PartialSignature {
        hash_to_g2(msg).mul(sk).into_affine()
    }

    /// verifies the partial signature under the signer's public key
    pub fn partial_verify(
        crs: &CRS,
        msg: &[u8],
        pk: &PublicKey,
        sig: &PartialSignature
    ) -> bool {
        let lhs = <Curve as Pairing>::pairing(pk, hash_to_g2(msg));
        let rhs = <Curve as Pairing>::pairing(crs.powers_of_g[0], sig);
        lhs == rhs
    }

    /// aggregates partial signatures to construct a threshold signature
    pub fn aggregate(
        crs: &CRS,
        ak: &AggregationKey,
        vk: &VerificationKey,
        partial_signatures: &HashMap<usize, PartialSignature>
    ) -> ThresholdSignature {
        // compute the nth root of unity
        let n = ak.n;
        let n_inv = F::from(1) / F::from(n as u64);

        // compute bitmap based on entries in partial_signatures
        let mut bitmap: Vec<F> = vec![F::from(0); n];
        for (i, _sig) in partial_signatures.iter() {
            bitmap[*i] = F::from(1);
        }

        //adjust the weights and bitmap polynomials
        // the weights vector is of size power of 2 - 1; lets pad
        let mut weights = ak.weights.clone();
        //compute sum of weights of active signers
        let total_active_weight = bitmap
            .iter()
            .zip(weights.iter())
            .fold(F::from(0), |acc, (&x, &y)| acc + (x * y));
        
        //weight's last element must the additive inverse of active weight
        weights[n-1] = F::from(0) - total_active_weight;
        // last element of bitmap must be 1 for our scheme
        bitmap[n-1] = F::from(1);
    
        //compute all the scalars we will need in the prover
        let ω: F = utils::nth_root_of_unity(n);
        let ω_inv: F = F::from(1) / ω;
    
        //compute all the polynomials we will need in the prover
        let z_of_x = utils::compute_vanishing_poly(n); //returns Z(X) = X^n - 1
        let l_n_minus_1_of_x = utils::lagrange_poly(n, n-1);
        let w_of_x = utils::interpolate_poly_over_mult_subgroup(&weights);
        let b_of_x = utils::interpolate_poly_over_mult_subgroup(&bitmap);
        let psw_of_x = compute_psw_poly(&weights, &bitmap);
        let psw_of_x_div_ω = utils::poly_domain_mult_ω(&psw_of_x, &ω_inv);
    
        //ParSumW(X) = ParSumW(X/ω) + W(X) · b(X) + Z(X) · Q1(X)
        let t_of_x = psw_of_x.sub(&psw_of_x_div_ω).sub(&w_of_x.mul(&b_of_x));
        let psw_wff_q_of_x = t_of_x.div(&z_of_x);
    
        //L_{n−1}(X) · ParSumW(X) = Z(X) · Q2(X) 
        let t_of_x = l_n_minus_1_of_x.mul(&psw_of_x);
        let psw_check_q_of_x = t_of_x.div(&z_of_x);
    
        //b(X) · b(X) − b(X) = Z(X) · Q3(X)
        let t_of_x = b_of_x.mul(&b_of_x).sub(&b_of_x);
        let b_wff_q_of_x = t_of_x.div(&z_of_x);
    
        //L_{n−1}(X) · (b(X) - 1) = Z(X) · Q4(X)
        let one_poly = utils::compute_constant_poly(&F::from(1));
        let t_of_x = l_n_minus_1_of_x.mul(&b_of_x.sub(&one_poly));
        let b_check_q_of_x = t_of_x.div(&z_of_x);
    
        let qz_com = ipa(&ak.qz_terms, &bitmap);
        let qx_com = ipa(&ak.qx_terms, &bitmap);
        let qx_mul_tau_com = ipa(&ak.qx_mul_tau_terms, &bitmap);

        // aggregate pubkey is the sum of all active public keys, multiplied by n_inv
        // this is computed using the fn for inner product argument with bitmap
        let agg_pk = ipa::<G1AffinePoint>(&ak.pks, &bitmap).mul(n_inv).into_affine();
        
        // aggregate sig is the sum of all partial signatures, multiplied by n_inv
        let partial_sigs = partial_signatures
            .values()
            .map(|x| x.to_owned())
            .collect::<Vec<PartialSignature>>();
        let agg_sig = add::<G2AffinePoint>(partial_sigs).mul(n_inv).into_affine();
    
        let parsum_of_tau_com = KZG::commit_g1(&crs, &psw_of_x).unwrap();
        let b_of_tau_com = KZG::commit_g1(&crs, &b_of_x).unwrap();
        let q1_of_tau_com = KZG::commit_g1(&crs, &psw_wff_q_of_x).unwrap();
        let q2_of_tau_com = KZG::commit_g1(&crs, &b_wff_q_of_x).unwrap();
        let q3_of_tau_com = KZG::commit_g1(&crs, &psw_check_q_of_x).unwrap();
        let q4_of_tau_com = KZG::commit_g1(&crs, &b_check_q_of_x).unwrap();
    
        // RO(SK, W, B, ParSum, Qx, Qz, Qx(τ ) · τ, Q1, Q2, Q3, Q4)
        let r = random_oracle(
            vk.sk_of_tau_com, 
            vk.w_of_tau_com,
            b_of_tau_com,
            parsum_of_tau_com,
            qx_com,
            qz_com,
            qx_mul_tau_com,
            q1_of_tau_com,
            q2_of_tau_com,
            q3_of_tau_com,
            q4_of_tau_com
        );
        let r_div_ω: F = r / ω;
    
        let psw_of_r_proof = KZG::compute_opening_proof(&crs, &psw_of_x, &r).unwrap();
        let w_of_r_proof = KZG::compute_opening_proof(&crs, &w_of_x, &r).unwrap();
        let b_of_r_proof = KZG::compute_opening_proof(&crs, &b_of_x, &r).unwrap();
        let psw_wff_q_of_r_proof = KZG::compute_opening_proof(&crs, &psw_wff_q_of_x, &r).unwrap();
        let psw_check_q_of_r_proof = KZG::compute_opening_proof(&crs, &psw_check_q_of_x, &r).unwrap();
        let b_wff_q_of_r_proof = KZG::compute_opening_proof(&crs, &b_wff_q_of_x, &r).unwrap();
        let b_check_q_of_r_proof = KZG::compute_opening_proof(&crs, &b_check_q_of_x, &r).unwrap();

        // batched opening argument as it is for the same point r
        let merged_proof: G1AffinePoint = (psw_of_r_proof
            + w_of_r_proof.mul(r.pow([1]))
            + b_of_r_proof.mul(r.pow([2]))
            + psw_wff_q_of_r_proof.mul(r.pow([3]))
            + psw_check_q_of_r_proof.mul(r.pow([4]))
            + b_wff_q_of_r_proof.mul(r.pow([5]))
            + b_check_q_of_r_proof.mul(r.pow([6]))).into();
    
        ThresholdSignature {
            agg_pk: agg_pk.clone(),
            agg_sig: agg_sig.clone(),
            agg_weight: total_active_weight,
            
            parsum_of_r_div_ω: psw_of_x.evaluate(&r_div_ω),
            opening_proof_r_div_ω: KZG::compute_opening_proof(&crs, &psw_of_x, &r_div_ω).unwrap(),
    
            parsum_of_r: psw_of_x.evaluate(&r),
            w_of_r: w_of_x.evaluate(&r),
            b_of_r: b_of_x.evaluate(&r),
            q1_of_r: psw_wff_q_of_x.evaluate(&r),
            q3_of_r: psw_check_q_of_x.evaluate(&r),
            q2_of_r: b_wff_q_of_x.evaluate(&r),
            q4_of_r: b_check_q_of_x.evaluate(&r),
            
            opening_proof_r: merged_proof.into(),
    
            parsum_of_tau_com: parsum_of_tau_com,
            b_of_tau_com: b_of_tau_com,
            q1_of_tau_com: q1_of_tau_com,
            q3_of_tau_com: q3_of_tau_com,
            q2_of_tau_com: q2_of_tau_com,
            q4_of_tau_com: q4_of_tau_com,
    
            qz_of_tau_com: qz_com,
            qx_of_tau_com: qx_com,
            qx_of_tau_mul_tau_com: qx_mul_tau_com,
        }
    }

    /// verifies whether the threshold signature is valid and 
    /// satisfies the desired threshold fraction
    pub fn verify(
        crs: &CRS,
        msg: &[u8],
        vk: &VerificationKey,
        π: &ThresholdSignature,
        fraction: (F, F) // e.g. (1,3) to denote 1/3 threshold
    ) -> bool {

        // check that the threshold is satisfied
        let (numerator, denominator) = fraction;
        check_or_return_false!(denominator * π.agg_weight >= numerator * vk.total_weight);

        // verify the signature first
        check_or_return_false!(Self::partial_verify(crs, msg, &π.agg_pk, &π.agg_sig));

        // compute nth root of unity
        let ω: F = utils::nth_root_of_unity(vk.n);
    
        //RO(SK, W, B, ParSum, Qx, Qz, Qx(τ ) · τ, Q1, Q2, Q3, Q4)
        let r = random_oracle(
            vk.sk_of_tau_com,
            vk.w_of_tau_com,
            π.b_of_tau_com,
            π.parsum_of_tau_com,
            π.qx_of_tau_com,
            π.qz_of_tau_com,
            π.qx_of_tau_mul_tau_com,
            π.q1_of_tau_com,
            π.q2_of_tau_com,
            π.q3_of_tau_com,
            π.q4_of_tau_com
        );
    
        // verify the polynomial openings at r and r / ω
        check_or_return_false!(verify_openings_in_proof(vk, π, r));
    
        let n: u64 = vk.n as u64;
        // this takes logarithmic computation, but concretely efficient
        let vanishing_of_r: F = r.pow([n]) - F::from(1);
    
        // compute L_i(r) using the relation L_i(x) = Z_V(x) / ( Z_V'(x) (x - ω^i) )
        // where Z_V'(x)^-1 = x / N for N = |V|.
        let ω_pow_n_minus_1 = ω.pow([n-1]);
        let l_n_minus_1_of_r = (ω_pow_n_minus_1 / F::from(n)) * (vanishing_of_r / (r - ω_pow_n_minus_1));
    
        //assert polynomial identity B(x) SK(x) = ask + Q_z(x) Z(x) + Q_x(x) x
        let lhs = <Curve as Pairing>::pairing(&π.b_of_tau_com, &vk.sk_of_tau_com);
        let x1 = <Curve as Pairing>::pairing(&π.qz_of_tau_com, &vk.z_of_tau_com);
        let x2 = <Curve as Pairing>::pairing(&π.qx_of_tau_com, &vk.tau_com);
        let x3 = <Curve as Pairing>::pairing(&π.agg_pk, &vk.h_0);
        let rhs = x1.add(x2).add(x3);
        check_or_return_false!(lhs == rhs);
    
        //assert checks on the public part
    
        //ParSumW(r) − ParSumW(r/ω) − W(r) · b(r) = Q(r) · (r^n − 1)
        let lhs = π.parsum_of_r - π.parsum_of_r_div_ω - π.w_of_r * π.b_of_r;
        let rhs = π.q1_of_r * vanishing_of_r;
        check_or_return_false!(lhs == rhs);
    
        //Ln−1(X) · ParSumW(X) = Z(X) · Q2(X)
        //TODO: compute l_n_minus_1_of_r in verifier -- dont put it in the proof.
        let lhs = l_n_minus_1_of_r * π.parsum_of_r;
        let rhs = vanishing_of_r * π.q3_of_r;
        check_or_return_false!(lhs == rhs);
    
        //b(r) * b(r) - b(r) = Q(r) · (r^n − 1)
        let lhs = π.b_of_r * π.b_of_r - π.b_of_r;
        let rhs = π.q2_of_r * vanishing_of_r;
        check_or_return_false!(lhs == rhs);
    
        //Ln−1(X) · (b(X) − 1) = Z(X) · Q4(X)
        let lhs = l_n_minus_1_of_r * (π.b_of_r - F::from(1));
        let rhs = vanishing_of_r * π.q4_of_r;
        check_or_return_false!(lhs == rhs);
    
        //run the degree check e([Qx(τ)]_1, [τ]_2) ?= e([Qx(τ)·τ]_1, [1]_2)
        let lhs = <Curve as Pairing>::pairing(&π.qx_of_tau_com, &vk.h_1);
        let rhs = <Curve as Pairing>::pairing(&π.qx_of_tau_mul_tau_com, &vk.h_0);
        check_or_return_false!(lhs == rhs);
    
        true
    }
}

/// computes a hash for the Fiat-Shamir heuristic
fn random_oracle(
    sk_com: G2AffinePoint,
    w_com: G1AffinePoint,
    b_com: G1AffinePoint,
    parsum_com: G1AffinePoint,
    qx_com: G1AffinePoint,
    qz_com: G1AffinePoint,
    qx_mul_x_com: G1AffinePoint,
    q1_com: G1AffinePoint,
    q2_com: G1AffinePoint,
    q3_com: G1AffinePoint,
    q4_com: G1AffinePoint,
) -> F {

    let mut serialized_data = Vec::new();
    sk_com.serialize_compressed(&mut serialized_data).unwrap();
    w_com.serialize_compressed(&mut serialized_data).unwrap();
    b_com.serialize_compressed(&mut serialized_data).unwrap();
    parsum_com.serialize_compressed(&mut serialized_data).unwrap();
    qx_com.serialize_compressed(&mut serialized_data).unwrap();
    qz_com.serialize_compressed(&mut serialized_data).unwrap();
    qx_mul_x_com.serialize_compressed(&mut serialized_data).unwrap();
    q1_com.serialize_compressed(&mut serialized_data).unwrap();
    q2_com.serialize_compressed(&mut serialized_data).unwrap();
    q3_com.serialize_compressed(&mut serialized_data).unwrap();
    q4_com.serialize_compressed(&mut serialized_data).unwrap();

    let mut hash_result = Sha256::digest(serialized_data.as_slice());
    hash_result[31] = 0u8; //this makes sure we get a number below modulus
    let hash_bytes = hash_result.as_slice();

    let mut hash_values: [u64; 4] = [0; 4];
    hash_values[0] = u64::from_le_bytes(hash_bytes[0..8].try_into().unwrap());
    hash_values[1] = u64::from_le_bytes(hash_bytes[8..16].try_into().unwrap());
    hash_values[2] = u64::from_le_bytes(hash_bytes[16..24].try_into().unwrap());
    hash_values[3] = u64::from_le_bytes(hash_bytes[24..32].try_into().unwrap());

    let bi = BigInteger256::new(hash_values);

    F::try_from(bi).unwrap()
}

fn verify_opening(
    vp: &VerificationKey, 
    commitment: &G1AffinePoint,
    point: &F, 
    evaluation: &F,
    opening_proof: &G1AffinePoint
) -> bool {
    let eval_com: G1AffinePoint = vp.g_0.clone().mul(evaluation).into();
    let point_com: G2AffinePoint = vp.h_0.clone().mul(point).into();

    let lhs = <Curve as Pairing>::pairing(commitment.clone() - eval_com, vp.h_0);
    let rhs = <Curve as Pairing>::pairing(opening_proof.clone(), vp.h_1 - point_com);
    
    lhs == rhs
}

fn verify_openings_in_proof(
    vk: &VerificationKey,
    π: &ThresholdSignature,
    r: F
) -> bool {
    //adjust the w_of_x_com
    let adjustment = F::from(0) - π.agg_weight;
    let adjustment_com = vk.l_n_minus_1_of_tau_com.mul(adjustment);
    let w_of_x_com: G1AffinePoint = (vk.w_of_tau_com + adjustment_com).into();

    let psw_of_r_argument = π.parsum_of_tau_com - vk.g_0.mul(π.parsum_of_r).into_affine();
    let w_of_r_argument = w_of_x_com - vk.g_0.mul(π.w_of_r).into_affine();
    let b_of_r_argument = π.b_of_tau_com - vk.g_0.mul(π.b_of_r).into_affine();
    let psw_wff_q_of_r_argument = π.q1_of_tau_com - vk.g_0.mul(π.q1_of_r).into_affine();
    let psw_check_q_of_r_argument = π.q3_of_tau_com - vk.g_0.mul(π.q3_of_r).into_affine();
    let b_wff_q_of_r_argument = π.q2_of_tau_com - vk.g_0.mul(π.q2_of_r).into_affine();
    let b_check_q_of_r_argument = π.q4_of_tau_com - vk.g_0.mul(π.q4_of_r).into_affine();

    let merged_argument: G1AffinePoint = (psw_of_r_argument
        + w_of_r_argument.mul(r.pow([1]))
        + b_of_r_argument.mul(r.pow([2]))
        + psw_wff_q_of_r_argument.mul(r.pow([3]))
        + psw_check_q_of_r_argument.mul(r.pow([4]))
        + b_wff_q_of_r_argument.mul(r.pow([5]))
        + b_check_q_of_r_argument.mul(r.pow([6]))).into_affine();

    let lhs = <Curve as Pairing>::pairing(
        merged_argument, 
        vk.h_0);
    let rhs = <Curve as Pairing>::pairing(
        π.opening_proof_r, 
        vk.h_1 - vk.h_0.mul(r).into_affine());
    check_or_return_false!(lhs == rhs);

    let ω: F = utils::nth_root_of_unity(vk.n);
    let r_div_ω: F = r / ω;

    verify_opening(
        vk,
        &π.parsum_of_tau_com,
        &r_div_ω,
        &π.parsum_of_r_div_ω,
        &π.opening_proof_r_div_ω
    )
}

fn preprocess_qz_contributions(
    q1_contributions: &Vec<Vec<G1AffinePoint>>
) -> Vec<G1AffinePoint> {
    let n = q1_contributions.len();
    let mut q1_coms = vec![];

    for i in 0..n {
        // extract party i's hints, from which we extract the term for i.
        let mut party_i_q1_com = q1_contributions[i][i].clone();
        for j in 0..n {
            if i != j {
                // extract party j's hints, from which we extract cross-term for party i
                let party_j_contribution = q1_contributions[j][i].clone();
                party_i_q1_com = party_i_q1_com.add(party_j_contribution).into();
            }
        }
        // the aggregation key contains a single term that 
        // is a product of all cross-terms and the ith term
        q1_coms.push(party_i_q1_com);
    }
    q1_coms
}

fn compute_psw_poly(
    weights: &Vec<Weight>,
    bitmap: &Vec<F>
) -> DensePolynomial<F> {
    let n = weights.len(); //power of 2 size
    assert_power_of_2!(n);

    let mut parsum = F::from(0);
    let mut evals = vec![];
    for i in 0..n {
        parsum += bitmap[i] * weights[i];
        evals.push(parsum);
    }

    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(evals, domain);
    eval_form.interpolate()    
}

/// computes the inner product argument between a vector of group elements and bitvector
fn ipa<T: AffineRepr>(elements: &Vec<T>, bitmap: &Vec<F>) -> T {
    elements
    .iter()
    .zip(bitmap.iter())
    .fold(T::zero(), |acc, (elem, bit)| {
        if *bit == F::from(1) { acc.add(elem).into_affine() } else { acc }
    })
}

/// adds up all the group elements in a collection
fn add<T: AffineRepr>(elements: impl IntoIterator<Item = T>) -> T {
    elements
        .into_iter()
        .fold(T::zero(), |acc, x| acc.add(&x).into_affine())
}

/// hashes a byte array to an elliptic curve group element
pub fn hash_to_g2(msg: impl AsRef<[u8]>) -> G2AffinePoint {
    const DST_G2: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let g2_mapper = MapToCurveBasedHasher::<
        G2ProjectivePoint,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(DST_G2.as_bytes())
    .unwrap();
    let q: G2AffinePoint = g2_mapper.hash(msg.as_ref()).unwrap();
    q
}

pub fn serialize<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    t.serialize_uncompressed(&mut buf).unwrap();
    buf
}

pub fn deserialize<T: CanonicalDeserialize>(buf: &[u8]) -> T {
    T::deserialize_uncompressed(buf).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_std::rand::Rng;
    use ark_std::test_rng;

    #[test]
    fn test_serialization() {
        let universe_n = 32;
        let num_signers = universe_n - 1;
        let msg = b"helloworld";

        let (crs, ak, vk, sks, epks) = sample_universe(universe_n);
        let sigs = sample_signing(num_signers, msg, &sks);
        let π = HinTS::aggregate(&crs, &ak, &vk, &sigs);

        // test (de)-serialization
        let serialized_vk = serialize(&vk);
        let deserialized_vk = deserialize::<VerificationKey>(&serialized_vk);

        let serialized_ak = serialize(&ak);
        let deserialized_ak = deserialize::<AggregationKey>(&serialized_ak);

        let serialized_π = serialize(&π);
        let deserialized_π = deserialize::<ThresholdSignature>(&serialized_π);

        let serialized_sk = serialize(&sks[0]);
        let deserialized_sk = deserialize::<SecretKey>(&serialized_sk);

        let serialized_pk = serialize(&epks[0].pk_i);
        let deserialized_pk = deserialize::<PublicKey>(&serialized_pk);

        let serialized_epk = serialize(&epks[0]);
        let deserialized_epk = deserialize::<ExtendedPublicKey>(&serialized_epk);

        let serialized_crs = serialize(&crs);
        let deserialized_crs = deserialize::<CRS>(&serialized_crs);

        assert_eq!(vk, deserialized_vk);
        assert_eq!(ak, deserialized_ak);
        assert_eq!(π, deserialized_π);
        assert_eq!(sks[0], deserialized_sk);
        assert_eq!(epks[0].pk_i, deserialized_pk);
        assert_eq!(epks[0], deserialized_epk);
        assert_eq!(crs, deserialized_crs);

        // print out sizes for our information
        println!("vk size: {}", serialized_vk.len());
        println!("ak size: {}", serialized_ak.len());
        println!("π size: {}", serialized_π.len());
        println!("sk size: {}", serialized_sk.len());
        println!("pk size: {}", serialized_pk.len());
        println!("epk size: {}", serialized_epk.len());
        println!("crs size: {}", serialized_crs.len());
    }

    #[test]
    fn it_works() {
        let universe_n = 32;
        let num_signers = universe_n - 1;
        let msg = b"hello";

        let (crs, ak, vk, sks, _) = sample_universe(universe_n);
        let sigs = sample_signing(num_signers, msg, &sks);

        let π = HinTS::aggregate(&crs, &ak, &vk, &sigs);

        let threshold = (F::from(1), F::from(3)); // 1/3
        assert!(HinTS::verify(&crs, msg, &vk, &π, threshold));

        // attack the proof
        let mut π_attack = π.clone();
        π_attack.agg_weight = F::from(1000000000); // some arbitrary weight
        assert!(!HinTS::verify(&crs, msg, &vk, &π_attack, threshold));

        // try a really high threshold of 99%
        assert!(!HinTS::verify(&crs, msg, &vk, &π_attack, (F::from(99), F::from(100))));
    }

    fn sample_signing(num_signers: usize, msg: &[u8], sks: &Vec<SecretKey>) -> HashMap<usize, PartialSignature> {
        //samples n-1 random bits
        let bitmap = sample_bitmap(num_signers, 0.75);

        // for all the active parties, sample partial signatures
        // filter our bitmap indices that are 1
        let mut sigs = HashMap::new();
        bitmap.iter().enumerate().for_each(|(i, &bit)| {
            if bit == F::from(1) { sigs.insert(i, HinTS::sign(msg, &sks[i])); }
        });

        sigs
    }

    fn sample_universe(n: usize) -> (
        CRS,
        AggregationKey,
        VerificationKey,
        Vec<SecretKey>,
        Vec<ExtendedPublicKey>
    ) {
        let num_signers = n - 1;
    
        // -------------- sample one-time SRS ---------------
        //run KZG setup
        let rng = &mut test_rng();
        let params = KZG::setup(n, rng).expect("Setup failed");
    
        // -------------- sample universe specific values ---------------
        //sample random keys
        let sks: Vec<SecretKey> = (0..num_signers)
            .map(|_| HinTS::keygen(rng))
            .collect();

        let epks = (0..num_signers)
            .map(|i| HinTS::hint_gen(&params, n, i, &sks[i]))
            .collect::<Vec<ExtendedPublicKey>>();

        //sample random weights for each party
        let weights = sample_weights(num_signers);
    
        // -------------- perform universe setup ---------------
        let signers_info: HashMap<usize, (Weight, ExtendedPublicKey)> = (0..num_signers)
            .map(|i| (i, (weights[i], epks[i].clone())))
            .collect();

        //run universe setup
        let (vk, ak) = HinTS::preprocess(n, &params, &signers_info);

        (params, ak, vk, sks, epks)
    }

    fn sample_weights(n: usize) -> Vec<F> {
        let rng = &mut test_rng();
        (0..n).map(|_| F::from(rng.gen_range(1..10)) + F::from(10)).collect()
    }
    
    /// n is the size of the bitmap, and probability is for true or 1.
    fn sample_bitmap(n: usize, probability: f64) -> Vec<F> {
        let rng = &mut test_rng();
        let mut bitmap = vec![];
        for _i in 0..n {
            //let r = u64::rand(&mut rng);
            let bit = rng.gen_bool(probability);
            bitmap.push(F::from(bit));
        }
        bitmap
    }
}
