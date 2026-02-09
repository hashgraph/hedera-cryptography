// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::PathBuf;
use std::io::Write;
use ark_bn254::{G1Affine, G2Affine, g1};
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, domain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{Zero, ops::*};
use ark_relations::utils::matrix::{self, Matrix};

use folding_schemes::folding::nova::decider_eth_circuit::DeciderEthCircuit;
use folding_schemes::folding::traits::Dummy;
use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen, CommitmentScheme};
use folding_schemes::folding::nova::{
    Nova,
    PreprocessorParam,
    ProverParams,
    VerifierParams,
    decider_eth::Decider as DeciderEth,
    decider_eth::Proof as EthProof,
    decider_eth::VerifierParam as VerifierParam
};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, Error, FoldingScheme};
use folding_schemes::folding::traits::CommittedInstanceOps;

use ark_ff::UniformRand;
use ark_snark::SNARK;
use ark_groth16::{Groth16, ProvingKey as Groth16ProvingKey, VerifyingKey as Groth16VerifyingKey};
use ark_crypto_primitives::crh::{
    sha256::Sha256,
    poseidon::constraints::{CRHGadget as PoseidonCRHGadget, CRHParametersVar as PoseidonCRHParametersVar},
    poseidon::CRH as PoseidonCRH,
    CRHSchemeGadget, CRHScheme
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
    OptimizationGoal, Result as R1CSResult,
    SynthesisError, SynthesisMode, Namespace
};

use rayon::prelude::*;

use super::{
    Circuit,
    PairingCurve,
    WRAPSError,
    ProvingKey as WRAPSProvingKey,
    VerificationKey as WRAPSVerificationKey,
    Fr, N, D, G1, G2
};

use crate::utils::ECFFTUtils;

pub struct Phase1SRS {
    powers_of_tau_g1: Vec<G1Affine>,
    powers_of_tau_g2: Vec<G2Affine>,
    powers_of_alpha_tau_g1: Vec<G1Affine>,
    powers_of_beta_tau_g1: Vec<G1Affine>,
    beta_g2: G2Affine,
}

pub struct Phase1Output {
    a_query: Vec<G1Affine>,
    b_g1_query: Vec<G1Affine>,
    b_g2_query: Vec<G2Affine>,
}

pub struct Phase2SRS {
    delta_g1: G1Affine,
    delta_g2: G2Affine,
    gamma_g2: G2Affine,
    gamma_abc_g1: Vec<G1Affine>,
    delta_abc_g1: Vec<G1Affine>,
    h_g1: Vec<G1Affine>,
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct CircuitConfig {
    pub num_constraints: usize,
    pub num_witness_variables: usize,
    pub num_instance_variables: usize,
}

fn load_from_file<T: CanonicalDeserialize>(path: &PathBuf) -> Result<T, Error> {
    let raw_data = std::fs::read(path)?;
    let data: T = T::deserialize_uncompressed(&*raw_data)?;
    Ok(data)
}

fn store_to_file<T: CanonicalSerialize>(path: &PathBuf, data: &T) -> Result<(), Error> {
    let mut raw_data = Vec::new();
    data.serialize_uncompressed(&mut raw_data)?;
    std::fs::write(path, &raw_data)?;
    Ok(())
}

const PAUSE: bool = false;
fn pause_until_enter() {
    if PAUSE {
        print!("Press Enter to continue...");
        std::io::stdout().flush().unwrap(); // make sure prompt shows before blocking

        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap(); // waits for Enter
    }
}

fn update_srs_helper_g1(prev_srs: &PathBuf, next_srs: &PathBuf, name: &str, multiplier: Fr, tau: Fr, is_vec: bool) {
    if is_vec {
        let prev_powers_of_tau_g1 = load_from_file::<Vec<G1Affine>>(&prev_srs.join(name)).unwrap();
        let new_powers_of_tau_g1 = prev_powers_of_tau_g1
            .iter()
            .enumerate()
            .map(|(i, g)| {
                let tau_pow_i = multiplier * tau.pow([i as u64]);
                g.mul(tau_pow_i).into_affine()
            })
            .collect::<Vec<G1Affine>>();
        store_to_file::<Vec<G1Affine>>(&next_srs.join(name), &new_powers_of_tau_g1).unwrap();
        drop(new_powers_of_tau_g1);
        drop(prev_powers_of_tau_g1);
    } else {
        let prev_power = load_from_file::<G1Affine>(&prev_srs.join(name)).unwrap();
        let new_power = prev_power.mul(multiplier).into_affine();
        store_to_file::<G1Affine>(&next_srs.join(name), &new_power).unwrap();
    }
}

fn update_srs_helper_g2(prev_srs: &PathBuf, next_srs: &PathBuf, name: &str, multiplier: Fr, tau: Fr, is_vec: bool) {
    if is_vec {
        let prev_powers_of_tau_g2 = load_from_file::<Vec<G2Affine>>(&prev_srs.join(name)).unwrap();
        let new_powers_of_tau_g2 = prev_powers_of_tau_g2
            .iter()
            .enumerate()
            .map(|(i, g)| {
                let tau_pow_i = multiplier * tau.pow([i as u64]);
                g.mul(tau_pow_i).into_affine()
            })
            .collect::<Vec<G2Affine>>();
        store_to_file::<Vec<G2Affine>>(&next_srs.join(name), &new_powers_of_tau_g2).unwrap();
        drop(new_powers_of_tau_g2);
        drop(prev_powers_of_tau_g2);
    } else {
        let prev_power = load_from_file::<G2Affine>(&prev_srs.join(name)).unwrap();
        let new_power = prev_power.mul(multiplier).into_affine();
        store_to_file::<G2Affine>(&next_srs.join(name), &new_power).unwrap();
    }
}

fn specialize_srs_helper_g1(
    state: &mut [G1Affine],
    matrix_path: &PathBuf,
    powers: &[G1Affine],
    num_constraints: usize,
    num_variables: usize)
{
    let matrix = load_from_file::<Matrix<Fr>>(&matrix_path).unwrap();
    let intermediate = (0..num_constraints)
        .into_par_iter()
        .fold(
            || vec![ark_bn254::G1Projective::zero(); num_variables + 1],
            |mut local, i| {
                let u_i = powers[i].into_group();
                for &(ref coeff, index) in &matrix[i] {
                    local[index] += u_i * coeff;
                }
                local
            }
        )
        .reduce (
            || vec![ark_bn254::G1Projective::zero(); num_variables + 1],
            |mut acc, local| {
                for (a, b) in acc.iter_mut().zip(local.iter()) {
                    *a += b;
                }
                acc
            }
        );

    let intermediate = intermediate
        .into_iter()
        .map(|p| p.into_affine())
        .collect::<Vec<G1Affine>>();

    drop(matrix);

    for (dst, src) in state.iter_mut().zip(intermediate.iter()) {
        *dst = (*dst + *src).into_affine();
    }
}

fn specialize_srs_helper_g2(
    state: &mut [G2Affine],
    matrix_path: &PathBuf,
    powers: &[G2Affine],
    num_constraints: usize,
    num_variables: usize)
{
    let matrix = load_from_file::<Matrix<Fr>>(&matrix_path).unwrap();
    let intermediate = (0..num_constraints)
        .into_par_iter()
        .fold(
            || vec![ark_bn254::G2Projective::zero(); num_variables + 1],
            |mut local, i| {
                let u_i = powers[i].into_group();
                for &(ref coeff, index) in &matrix[i] {
                    local[index] += u_i * coeff;
                }
                local
            }
        )
        .reduce (
            || vec![ark_bn254::G2Projective::zero(); num_variables + 1],
            |mut acc, local| {
                for (a, b) in acc.iter_mut().zip(local.iter()) {
                    *a += b;
                }
                acc
            }
        );

    let intermediate = intermediate
        .into_iter()
        .map(|p| p.into_affine())
        .collect::<Vec<G2Affine>>();

    drop(matrix);

    for (dst, src) in state.iter_mut().zip(intermediate.iter()) {
        *dst = (*dst + *src).into_affine();
    }
}


pub struct WRAPSPreprocessing {}

impl WRAPSPreprocessing {

    /// Performs the trusted setup for WRAPS, producing the WRAPSProvingKey and WRAPSVerificationKey.
    pub fn trusted_wraps_setup() -> Result<(WRAPSProvingKey, WRAPSVerificationKey), WRAPSError> {
        let mut rng = ark_std::rand::rngs::OsRng;
        let F_circuit = Circuit::new(())
            .map_err(|_| WRAPSError::CryptographyError)?;

        let poseidon_config = poseidon_canonical_config::<Fr>();

        let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
        // Generate Nova parameters for the WRAPS folding circuit.
        let (nova_pp, nova_vp) = N::preprocess(
            &mut rng,
            &nova_preprocess_params
        ).map_err(|_| WRAPSError::CryptographyError)?;

        let pp_hash = nova_vp.pp_hash().map_err(|_| WRAPSError::CryptographyError)?;

        let circuit = DeciderEthCircuit::<G1, G2>::dummy((
            nova_vp.clone().r1cs,
            nova_vp.clone().cf_r1cs,
            nova_pp.clone().cf_cs_pp,
            nova_pp.clone().poseidon_config,
            (),
            (),
            F_circuit.state_len(),
            2, // Nova's running CommittedInstance contains 2 commitments
        ));

        // get the Groth16 specific setup for the circuit
        let (g16_pk, g16_vk) = Self::trusted_groth_setup(circuit)?;

        let decider_pp = (g16_pk, nova_pp.clone().cs_pp);
        let decider_vp = VerifierParam {
            pp_hash,
            snark_vp: g16_vk,
            cs_vp: nova_vp.clone().cs_vp,
        };

        Ok((
            WRAPSProvingKey { nova_pp, decider_pp },
            WRAPSVerificationKey { nova_vp, decider_vp }
        ))
    }

    fn trusted_groth_setup<C: ConstraintSynthesizer<Fr>>(circuit: C)
        -> Result<(Groth16ProvingKey<PairingCurve>, Groth16VerifyingKey<PairingCurve>), WRAPSError> {
        let mut rng = ark_std::rand::rngs::OsRng;
        let (g16_pk, g16_vk) = Groth16::<PairingCurve>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| Error::SNARKSetupFail(e.to_string()))
            .map_err(|_| WRAPSError::CryptographyError)?;

        Ok((g16_pk, g16_vk))
    }

    /// creates an initial SRS for Groth16, using tau = 1, and alpha, beta = 1
    pub fn create_init_srs_phase1(circuit_config: &CircuitConfig, path: &PathBuf) {
        // let us figure out the circuit dimensions
        // domain_size is computed the same way (and then padded to the next power of 2)
        let n = circuit_config.num_constraints + circuit_config.num_instance_variables;
        let domain = GeneralEvaluationDomain::<Fr>::new(n)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge).unwrap();
        let domain_size = domain.size();

        // generate default SRS elements and store them to disk, so we can purge them from memory

        // generate default powers of tau in G1
        let powers_of_tau_g1: Vec<G1Affine> = vec![G1Affine::generator(); 2*domain_size]; // {Gx:i} | i=0..2n-2}
        store_to_file::<Vec<G1Affine>>(&path.join("powers_of_tau_g1.bin"), &powers_of_tau_g1).unwrap();
        drop(powers_of_tau_g1);

        // generate default powers of tau in G2
        let powers_of_tau_g2: Vec<G2Affine> = vec![G2Affine::generator(); domain_size]; // {Hx:i} | i=0..2n-2}
        // store to file so we can purge this data structure from memory
        store_to_file::<Vec<G2Affine>>(&path.join("powers_of_tau_g2.bin"), &powers_of_tau_g2).unwrap();
        drop(powers_of_tau_g2);

        // generate default powers of alpha * tau in G1
        let powers_of_alpha_tau_g1: Vec<G1Affine> = vec![G1Affine::generator(); domain_size]; // {Gαx:i} | i=0..n-1}
        store_to_file::<Vec<G1Affine>>(&path.join("powers_of_alpha_tau_g1.bin"), &powers_of_alpha_tau_g1).unwrap();
        drop(powers_of_alpha_tau_g1);

        // generate default powers of beta * tau in G1
        let powers_of_beta_tau_g1: Vec<G1Affine> = vec![G1Affine::generator(); domain_size]; // {Gβx:i} | i=0..n-1}
        store_to_file::<Vec<G1Affine>>(&path.join("powers_of_beta_tau_g1.bin"),&powers_of_beta_tau_g1).unwrap();
        drop(powers_of_beta_tau_g1);

        // generate default beta in G2
        let beta_g2: G2Affine = G2Affine::generator();
        store_to_file::<G2Affine>(&path.join("beta_g2.bin"), &beta_g2).unwrap();

    }

    pub fn update_srs_phase1(circuit_config: &CircuitConfig, prev_srs: &PathBuf, next_srs: &PathBuf) {
        type D<F> = GeneralEvaluationDomain<F>;
        let n = circuit_config.num_constraints + circuit_config.num_instance_variables;
        let domain = D::new(n)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge).unwrap();

        let mut rng = ark_std::rand::rngs::OsRng;
        let tau: Fr = domain.sample_element_outside_domain(&mut rng);
        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);

        update_srs_helper_g1(prev_srs, next_srs, "powers_of_tau_g1.bin", Fr::from(1u64), tau, true);
        update_srs_helper_g2(prev_srs, next_srs, "powers_of_tau_g2.bin", Fr::from(1u64), tau, true);
        update_srs_helper_g1(prev_srs, next_srs, "powers_of_alpha_tau_g1.bin", alpha, tau, true);
        update_srs_helper_g1(prev_srs, next_srs, "powers_of_beta_tau_g1.bin", beta, tau, true);
        update_srs_helper_g2(prev_srs, next_srs, "beta_g2.bin", beta, Fr::from(1u64), false);
    }

    pub fn update_srs_phase2(prev_srs: &PathBuf, next_srs: &PathBuf) {
        let mut rng = ark_std::rand::rngs::OsRng;
        let delta = Fr::rand(&mut rng);
        let gamma = Fr::rand(&mut rng);

        let delta_inverse = delta.inverse().unwrap();
        let gamma_inverse = gamma.inverse().unwrap();

        update_srs_helper_g1(prev_srs, next_srs, "delta_g1.bin", delta, Fr::from(1u64), false);
        update_srs_helper_g2(prev_srs, next_srs, "delta_g2.bin", delta, Fr::from(1u64), false);
        update_srs_helper_g2(prev_srs, next_srs, "gamma_g2.bin", gamma, Fr::from(1u64), false);
        update_srs_helper_g1(prev_srs, next_srs, "gamma_abc_g1.bin", gamma_inverse, Fr::from(1u64), true);
        update_srs_helper_g1(prev_srs, next_srs, "delta_abc_g1.bin", delta_inverse, Fr::from(1u64), true);
        update_srs_helper_g1(prev_srs, next_srs, "h_g1.bin", delta_inverse, Fr::from(1u64), true);
    }

    pub fn specialize_srs(
        circuit_config: &CircuitConfig, // params related to circuit dimensions
        r1cs_matrix_path: &PathBuf, // path to the R1CS matrices for the circuit
        p1_srs: &PathBuf, // input to specialization, that is output by last phase 1 update
        p1_out: &PathBuf, // output that will be used for phase 2 SRS specialization
        p2_srs: &PathBuf, // output that will be used as phase 2 starting SRS
    ) {
        pause_until_enter();
        let n = circuit_config.num_constraints + circuit_config.num_instance_variables;
        let domain = GeneralEvaluationDomain::<Fr>::new(n)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge).unwrap();
        let ds = domain.size();

        // some useful values
        let num_constraints = circuit_config.num_constraints;
        let num_variables = (circuit_config.num_instance_variables - 1) + circuit_config.num_witness_variables;
        let start_index = 0;
        let end_index = circuit_config.num_instance_variables;

        let matrix_a_path = r1cs_matrix_path.join("matrix_A.bin");
        let matrix_b_path = r1cs_matrix_path.join("matrix_B.bin");
        let matrix_c_path = r1cs_matrix_path.join("matrix_C.bin");

        let powers_of_tau_g1_path = p1_srs.join("powers_of_tau_g1.bin");
        let powers_of_tau_g2_path = p1_srs.join("powers_of_tau_g2.bin");
        let powers_of_beta_tau_g1_path = p1_srs.join("powers_of_beta_tau_g1.bin");
        let powers_of_alpha_tau_g1_path = p1_srs.join("powers_of_alpha_tau_g1.bin");

        let ifft_of_powers_of_tau_g1_path = p1_out.join("ifft_of_powers_of_tau_g1.bin");
        let ifft_of_powers_of_tau_g2_path = p1_out.join("ifft_of_powers_of_tau_g2.bin");
        let ifft_of_powers_of_alpha_tau_g1_path = p1_out.join("ifft_of_powers_of_alpha_tau_g1.bin");
        let ifft_of_powers_of_beta_tau_g1_path = p1_out.join("ifft_of_powers_of_beta_tau_g1.bin");

        let phase1_powers_of_tau_g1 = load_from_file::<Vec<G1Affine>>(&powers_of_tau_g1_path).unwrap();
        let start = std::time::Instant::now();
        let ifft_of_powers_of_tau_g1  = ECFFTUtils::ifft::<ark_bn254::G1Projective>(&phase1_powers_of_tau_g1[..ds]);
        println!("IFFT (powers_of_tau_g1) took {:?}", start.elapsed());
        store_to_file(&ifft_of_powers_of_tau_g1_path, &ifft_of_powers_of_tau_g1).unwrap();
        drop(phase1_powers_of_tau_g1);

        let phase1_powers_of_tau_g2 = load_from_file::<Vec<G2Affine>>(&powers_of_tau_g2_path).unwrap();
        let start = std::time::Instant::now();
        let ifft_of_powers_of_tau_g2  = ECFFTUtils::ifft::<ark_bn254::G2Projective>(&phase1_powers_of_tau_g2[..ds]);
        println!("IFFT (powers_of_tau_g2) took {:?}", start.elapsed());
        store_to_file(&ifft_of_powers_of_tau_g2_path, &ifft_of_powers_of_tau_g2).unwrap();
        drop(phase1_powers_of_tau_g2);

        let phase1_powers_of_alpha_tau_g1 = load_from_file::<Vec<G1Affine>>(&powers_of_alpha_tau_g1_path).unwrap();
        let start = std::time::Instant::now();
        let ifft_of_powers_of_alpha_tau_g1 = ECFFTUtils::ifft::<ark_bn254::G1Projective>(&phase1_powers_of_alpha_tau_g1);
        println!("IFFT (powers_of_alpha_tau_g1) took {:?}", start.elapsed());
        store_to_file(&ifft_of_powers_of_alpha_tau_g1_path, &ifft_of_powers_of_alpha_tau_g1).unwrap();
        drop(phase1_powers_of_alpha_tau_g1);

        let phase1_powers_of_beta_tau_g1 = load_from_file::<Vec<G1Affine>>(&powers_of_beta_tau_g1_path).unwrap();
        let start = std::time::Instant::now();
        let ifft_of_powers_of_beta_tau_g1 = ECFFTUtils::ifft::<ark_bn254::G1Projective>(&phase1_powers_of_beta_tau_g1);
        println!("IFFT (powers_of_beta_tau_g1) took {:?}", start.elapsed());
        store_to_file(&ifft_of_powers_of_beta_tau_g1_path, &ifft_of_powers_of_beta_tau_g1).unwrap();
        drop(phase1_powers_of_beta_tau_g1);

        pause_until_enter();

        /* ---------------------------- begin compute h_g1 ---------------------------- */
        let phase1_powers_of_tau_g1 = load_from_file::<Vec<G1Affine>>(&powers_of_tau_g1_path).unwrap();
        let mut h_g1 = vec![G1Affine::zero(); domain.size() - 1];
        let start = std::time::Instant::now();
        for i in 0..=(domain.size()-2) {
            h_g1[i] = (phase1_powers_of_tau_g1[i + domain.size()] - phase1_powers_of_tau_g1[i]).into_affine();
        }
        println!("Computing h_g1 took {:?}", start.elapsed());
        store_to_file::<Vec<G1Affine>>(&p2_srs.join("h_g1.bin"), &h_g1).unwrap();
        drop(h_g1);
        drop(phase1_powers_of_tau_g1);
        /* ---------------------------- end compute h_g1 ---------------------------- */

        pause_until_enter();

        /* ---------------------------- begin compute b_g2 ---------------------------- */
        let mut b_g2 = vec![G2Affine::zero(); num_variables + 1];
        let matrix_b = load_from_file::<Matrix<Fr>>(&matrix_b_path).unwrap();
        let start = std::time::Instant::now();
        specialize_srs_helper_g2(&mut b_g2, &matrix_b_path, &ifft_of_powers_of_tau_g2, num_constraints, num_variables);
        println!("Computing b_g2 took {:?}", start.elapsed());
        store_to_file::<Vec<G2Affine>>(&p1_out.join("b_g2_query.bin"), &b_g2).unwrap();
        drop(matrix_b);
        drop(b_g2);
        /* ---------------------------- end compute b_g2 ---------------------------- */

        pause_until_enter();

        let mut abc_g1 = vec![G1Affine::zero(); num_variables + 1];
        let mut a_g1 = vec![G1Affine::zero(); num_variables + 1];
        let mut b_g1 = vec![G1Affine::zero(); num_variables + 1];

        /* ---------------------------- begin dummy constraints ---------------------------- */
        println!("Initializing a_g1 and abc_g1 for dummy constraints...");
        // this handles the dummy constraints x * 0 = 0 for non-malleability
        a_g1[start_index..end_index].copy_from_slice(&ifft_of_powers_of_tau_g1[(start_index + num_constraints)..(end_index + num_constraints)]);
        abc_g1[start_index..end_index].copy_from_slice(&ifft_of_powers_of_beta_tau_g1[(start_index + num_constraints)..(end_index + num_constraints)]);
        /* ---------------------------- end dummy constraints ---------------------------- */


        /* ---------------------------- begin compute abc_g1, a_g1, b_g1 ---------------------------- */
        let start = std::time::Instant::now();
        specialize_srs_helper_g1(&mut abc_g1, &matrix_a_path, &ifft_of_powers_of_beta_tau_g1, num_constraints, num_variables);
        println!("Updating abc_g1 using powers_of_beta_tau_g1 took {:?}", start.elapsed());

        pause_until_enter();

        let start = std::time::Instant::now();
        specialize_srs_helper_g1(&mut abc_g1, &matrix_b_path, &ifft_of_powers_of_alpha_tau_g1, num_constraints, num_variables);
        println!("Updating abc_g1 using powers_of_alpha_tau_g1 took {:?}", start.elapsed());

        pause_until_enter();

        let start = std::time::Instant::now();
        specialize_srs_helper_g1(&mut a_g1, &matrix_a_path, &ifft_of_powers_of_tau_g1, num_constraints, num_variables);
        println!("Updating a_g1 using powers_of_tau_g1 took {:?}. ", start.elapsed());

        let start = std::time::Instant::now();
        specialize_srs_helper_g1(&mut b_g1, &matrix_b_path, &ifft_of_powers_of_tau_g1, num_constraints, num_variables);
        println!("Updating b_g1 using powers_of_tau_g1 took {:?}. ", start.elapsed());

        let start = std::time::Instant::now();
        specialize_srs_helper_g1(&mut abc_g1, &matrix_c_path, &ifft_of_powers_of_tau_g1, num_constraints, num_variables);
        println!("Updating abc_g1 using powers_of_tau_g1 took {:?}. ", start.elapsed());

        /* ---------------------------- end compute abc_g1, a_g1, b_g1 ---------------------------- */

        // we use delta and gamma as 1 for this step
        let mut gamma_abc_g1 = abc_g1;
        let delta_abc_g1 = gamma_abc_g1.split_off(circuit_config.num_instance_variables);

        let delta_g1 = G1Affine::generator();
        let delta_g2 = G2Affine::generator();
        let gamma_g2 = G2Affine::generator();

        // store phase 1 output to disk
        store_to_file::<Vec<G1Affine>>(&p1_out.join("a_query.bin"), &a_g1).unwrap();
        store_to_file::<Vec<G1Affine>>(&p1_out.join("b_g1_query.bin"), &b_g1).unwrap();

        // store phase 2 SRS to disk
        store_to_file::<G1Affine>(&p2_srs.join("delta_g1.bin"), &delta_g1).unwrap();
        store_to_file::<G2Affine>(&p2_srs.join("delta_g2.bin"), &delta_g2).unwrap();
        store_to_file::<G2Affine>(&p2_srs.join("gamma_g2.bin"), &gamma_g2).unwrap();
        store_to_file::<Vec<G1Affine>>(&p2_srs.join("gamma_abc_g1.bin"), &gamma_abc_g1).unwrap();
        store_to_file::<Vec<G1Affine>>(&p2_srs.join("delta_abc_g1.bin"), &delta_abc_g1).unwrap();

    }

    pub fn finish_groth_setup(
        p1_srs: &PathBuf,
        p1_out: &PathBuf,
        p2_srs: &PathBuf
    ) -> Result<(Groth16ProvingKey<PairingCurve>, Groth16VerifyingKey<PairingCurve>), Error> {

        let srs1 = Phase1SRS {
            powers_of_tau_g1: load_from_file::<Vec<G1Affine>>(&p1_srs.join("powers_of_tau_g1.bin"))?,
            powers_of_tau_g2: load_from_file::<Vec<G2Affine>>(&p1_srs.join("powers_of_tau_g2.bin"))?,
            powers_of_alpha_tau_g1: load_from_file::<Vec<G1Affine>>(&p1_srs.join("powers_of_alpha_tau_g1.bin"))?,
            powers_of_beta_tau_g1: load_from_file::<Vec<G1Affine>>(&p1_srs.join("powers_of_beta_tau_g1.bin"))?,
            beta_g2: load_from_file::<G2Affine>(&p1_srs.join("beta_g2.bin"))?,
        };

        let phase1out = Phase1Output {
            a_query: load_from_file::<Vec<G1Affine>>(&p1_out.join("a_query.bin"))?,
            b_g1_query: load_from_file::<Vec<G1Affine>>(&p1_out.join("b_g1_query.bin"))?,
            b_g2_query: load_from_file::<Vec<G2Affine>>(&p1_out.join("b_g2_query.bin"))?,
        };

        let srs2 = Phase2SRS {
            delta_g1: load_from_file::<G1Affine>(&p2_srs.join("delta_g1.bin"))?,
            delta_g2: load_from_file::<G2Affine>(&p2_srs.join("delta_g2.bin"))?,
            gamma_g2: load_from_file::<G2Affine>(&p2_srs.join("gamma_g2.bin"))?,
            gamma_abc_g1: load_from_file::<Vec<G1Affine>>(&p2_srs.join("gamma_abc_g1.bin"))?,
            delta_abc_g1: load_from_file::<Vec<G1Affine>>(&p2_srs.join("delta_abc_g1.bin"))?,
            h_g1: load_from_file::<Vec<G1Affine>>(&p2_srs.join("h_g1.bin"))?,
        };

        let g16_vk = Groth16VerifyingKey {
            alpha_g1: srs1.powers_of_alpha_tau_g1[0],
            beta_g2: srs1.beta_g2,
            gamma_g2: srs2.gamma_g2,
            delta_g2: srs2.delta_g2,
            gamma_abc_g1: srs2.gamma_abc_g1.to_vec(),
        };

        let g16_pk = Groth16ProvingKey {
            vk: g16_vk.clone(),
            beta_g1: srs1.powers_of_beta_tau_g1[0],
            delta_g1: srs2.delta_g1,
            a_query: phase1out.a_query.clone(),
            b_g1_query: phase1out.b_g1_query.clone(),
            b_g2_query: phase1out.b_g2_query.clone(),
            h_query: srs2.h_g1.clone(),
            l_query: srs2.delta_abc_g1.to_vec(),
        };

        Ok((g16_pk, g16_vk))
    }

}


#[cfg(test)]
mod end_to_end_tests {
    use super::*;

    #[test]
    fn wraps_trusted_setup() {
        let (pk, vk) = WRAPSPreprocessing::trusted_wraps_setup().unwrap();
        let (nova_pp_serialized, decider_pp_serialized) = pk.serialize().unwrap();
        let (nova_vp_serialized, decider_vp_serialized) = vk.serialize().unwrap();

        let cwd = std::env::current_dir().unwrap();
        std::fs::write(cwd.join("resources/nova_pp.bin"), &nova_pp_serialized).unwrap();
        std::fs::write(cwd.join("resources/nova_vp.bin"), &nova_vp_serialized).unwrap();
        std::fs::write(cwd.join("resources/decider_pp.bin"), &decider_pp_serialized).unwrap();
        std::fs::write(cwd.join("resources/decider_vp.bin"), &decider_vp_serialized).unwrap();
    }
}


#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::merkle_tree::Path;
    // For randomness (during paramgen and proof generation)
    use ark_std::rand::{Rng, RngCore, SeedableRng};
    use super::*;

    use ark_snark::CircuitSpecificSetupSNARK;
    // For benchmarking
    use std::time::{Duration, Instant};
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
    };
    use ark_std::test_rng;

    fn extract_circuit<C: ConstraintSynthesizer<Fr>>(circuit: C, path: &PathBuf) {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.finalize();

        let matrices = &cs.to_matrices().unwrap()["R1CS"];

        let circuit_config = CircuitConfig {
            num_constraints: cs.num_constraints(),
            num_instance_variables: cs.num_instance_variables(),
            num_witness_variables: cs.num_witness_variables(),
        };

        store_to_file(&path.join("matrix_A.bin"), &matrices[0]).unwrap();
        store_to_file(&path.join("matrix_B.bin"), &matrices[1]).unwrap();
        store_to_file(&path.join("matrix_C.bin"), &matrices[2]).unwrap();

        store_to_file(&path.join("circuit_config.bin"), &circuit_config).unwrap();
    }

    fn sample_ceremony_groth_setup()
        -> Result<(Groth16ProvingKey<PairingCurve>, Groth16VerifyingKey<PairingCurve>), WRAPSError> {
        let circuit_config = load_from_file::<CircuitConfig>(
            &PathBuf::from("/Users/rohit/tss/circuit/circuit_config.bin")
        ).unwrap();

        // coordinator must create the initial SRS
        WRAPSPreprocessing::create_init_srs_phase1(
            &circuit_config,
            &PathBuf::from("/Users/rohit/tss/coordinator/phase1_init")
        );

        // three parties take turns updating the SRS
        WRAPSPreprocessing::update_srs_phase1(
            &circuit_config,
            &PathBuf::from("/Users/rohit/tss/coordinator/phase1_init"),
            &PathBuf::from("/Users/rohit/tss/node1/phase1")
        );
        WRAPSPreprocessing::update_srs_phase1(
            &circuit_config,
            &PathBuf::from("/Users/rohit/tss/node1/phase1"),
            &PathBuf::from("/Users/rohit/tss/node2/phase1")
        );
        WRAPSPreprocessing::update_srs_phase1(
            &circuit_config,
            &PathBuf::from("/Users/rohit/tss/node2/phase1"),
            &PathBuf::from("/Users/rohit/tss/node3/phase1")
        );

        // coordianator specialzes the SRS to the circuit
        WRAPSPreprocessing::specialize_srs(
            &circuit_config,
            &PathBuf::from("/Users/rohit/tss/circuit"),
            &PathBuf::from("/Users/rohit/tss/node3/phase1"),
            &PathBuf::from("/Users/rohit/tss/coordinator/phase1_output"),
            &PathBuf::from("/Users/rohit/tss/coordinator/phase2_init"),
        );

        // three parties take turns updating the phase 2 SRS
        WRAPSPreprocessing::update_srs_phase2(
            &PathBuf::from("/Users/rohit/tss/coordinator/phase2_init"),
            &PathBuf::from("/Users/rohit/tss/node1/phase2")
        );
        WRAPSPreprocessing::update_srs_phase2(
            &PathBuf::from("/Users/rohit/tss/node1/phase2"),
            &PathBuf::from("/Users/rohit/tss/node2/phase2")
        );
        WRAPSPreprocessing::update_srs_phase2(
            &PathBuf::from("/Users/rohit/tss/node2/phase2"),
            &PathBuf::from("/Users/rohit/tss/node3/phase2")
        );

        // finalize the Groth16 keys
        let (g16_pk, g16_vk) = WRAPSPreprocessing::finish_groth_setup(
            &PathBuf::from("/Users/rohit/tss/node3/phase1"), // last SRS phase 1 path
            &PathBuf::from("/Users/rohit/tss/coordinator/phase1_output"), // phase 1 output path
            &PathBuf::from("/Users/rohit/tss/node3/phase2"), // last SRS phase 2 path
        ).unwrap();

        Ok((g16_pk, g16_vk))
    }

    /// This is an implementation of MiMC, specifically a
    /// variant named `LongsightF322p3` for BLS12-377.
    /// See http://eprint.iacr.org/2016/492 for more
    /// information about this construction.
    ///
    /// ```
    /// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
    ///     for i from 0 up to 321 {
    ///         xL, xR := xR + (xL + Ci)^3, xL
    ///     }
    ///     return xL
    /// }
    /// ```
    fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
        assert_eq!(constants.len(), MIMC_ROUNDS);

        for i in 0..MIMC_ROUNDS {
            let mut tmp1 = xl;
            tmp1.add_assign(&constants[i]);
            let mut tmp2 = tmp1;
            tmp2.square_in_place();
            tmp2.mul_assign(&tmp1);
            tmp2.add_assign(&xr);
            xr = xl;
            xl = tmp2;
        }

        xl
    }

    /// This is our demo circuit for proving knowledge of the
    /// preimage of a MiMC hash invocation.
    #[derive(Copy, Clone)]
    struct MiMCDemo<'a, F: Field> {
        xl: Option<F>,
        xr: Option<F>,
        output: Option<F>,
        constants: &'a [F],
    }

    /// Our demo circuit implements this `Circuit` trait which
    /// is used during paramgen and proving in order to
    /// synthesize the constraint system.
    impl<'a, F: PrimeField> ConstraintSynthesizer<F> for MiMCDemo<'a, F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            assert_eq!(self.constants.len(), MIMC_ROUNDS);

            // Allocate the first component of the preimage.
            let mut xl = FpVar::new_witness(cs.clone(), || {
                self.xl.ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Allocate the second component of the preimage.
            let mut xr = FpVar::new_witness(cs.clone(), || {
                self.xr.ok_or(SynthesisError::AssignmentMissing)
            })?;

            // Allocate the output of the MiMC hash as a public input.
            let output = FpVar::new_input(cs.clone(), || {
                self.output.ok_or(SynthesisError::AssignmentMissing)
            })?;

            for i in 0..MIMC_ROUNDS {
                // tmp = (xL + Ci)^2
                let tmp = (&xl + self.constants[i]).square()?;

                // new_xL = xR + (xL + Ci)^3
                let new_xl = tmp * (&xl + self.constants[i]) + xr;

                // xR = xL
                xr = xl;

                // xL = new_xL
                xl = new_xl;
            }
            // Enforce that the output is correct.
            output.enforce_equal(&xl)?;

            Ok(())
        }
    }

    const MIMC_ROUNDS: usize = 32222;
    const USE_MPC_CEREMONY: bool = true;
    const PREPROCESS_CIRCUIT: bool = true;

    #[test]
    fn test_mimc_groth16() {
        // We're going to use the Groth16 proving system.
        use ark_groth16::Groth16;

        rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build_global()
            .unwrap(); // can only be called once

        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        // Generate the MiMC round constants
        let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

        println!("Creating parameters...");

        // Create parameters for our circuit
        let (pk, vk) = {
            let c = MiMCDemo::<Fr> {
                xl: None,
                xr: None,
                output: None,
                constants: &constants,
            };

            if USE_MPC_CEREMONY {
                if PREPROCESS_CIRCUIT {
                    extract_circuit(c, &PathBuf::from("/Users/rohit/tss/circuit"));
                }
                sample_ceremony_groth_setup().unwrap()
            } else {
                WRAPSPreprocessing::trusted_groth_setup(c).unwrap()
            }
        };

        // Prepare the verification key (for proof verification)
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        println!("Creating proofs...");

        // Let's benchmark stuff!
        const SAMPLES: u32 = 5;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        // Just a place to put the proof data, so we can
        // benchmark deserialization.
        // let mut proof_vec = vec![];

        for _ in 0..SAMPLES {
            // Generate a random preimage and compute the image
            let xl = rng.gen();
            let xr = rng.gen();
            let image = mimc(xl, xr, &constants);

            // proof_vec.truncate(0);

            let start = Instant::now();
            {
                // Create an instance of our circuit (with the
                // witness)
                let c = MiMCDemo {
                    xl: Some(xl),
                    xr: Some(xr),
                    output: Some(image),
                    constants: &constants,
                };

                let cs = ark_relations::gr1cs::ConstraintSystem::new_ref();
                cs.set_mode(ark_relations::gr1cs::SynthesisMode::Prove {
                    construct_matrices: true,
                    generate_lc_assignments: false,
                });
                c.generate_constraints(cs.clone()).unwrap();
                cs.finalize();
                assert!(cs.is_satisfied().unwrap());

                // Create a groth16 proof with our parameters.
                let proof = Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
                assert!(
                    Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[image], &proof).unwrap() &&
                    Groth16::<Bn254>::verify(&vk, &[image], &proof).unwrap()
                );
            }

            total_proving += start.elapsed();

            let start = Instant::now();

            total_verifying += start.elapsed();
        }
        let proving_avg = total_proving / SAMPLES;
        let proving_avg =
            proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

        let verifying_avg = total_verifying / SAMPLES;
        let verifying_avg =
            verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_millis() as f64);

        println!("Average proving time: {:?} seconds", proving_avg);
        println!("Average verifying time: {:?} milliseconds", verifying_avg);
    }

}