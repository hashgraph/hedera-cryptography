// SPDX-License-Identifier: Apache-2.0 OR MIT

use ark_bn254::{G1Affine, G2Affine, g1};
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, domain};
use ark_std::{Zero, ops::*};
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

use super::{
    Circuit,
    PairingCurve,
    WRAPSError,
    ProvingKey as WRAPSProvingKey,
    VerificationKey as WRAPSVerificationKey,
    Fr, N, D, G1, G2
};

use crate::utils::{FFTUtils, ECFFTUtils};

pub struct Phase1SRS {
    powers_of_tau_g1: Vec<G1Affine>,
    powers_of_tau_g2: Vec<G2Affine>,
    powers_of_alpha_tau_g1: Vec<G1Affine>,
    powers_of_alpha_tau_g2: Vec<G2Affine>,
    powers_of_beta_tau_g1: Vec<G1Affine>,
    powers_of_beta_tau_g2: Vec<G2Affine>,
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

pub struct WRAPSPreprocessing {}

impl WRAPSPreprocessing {

    /// Performs the trusted setup for WRAPS, producing the WRAPSProvingKey and WRAPSVerificationKey.
    pub fn trusted_setup() -> Result<(WRAPSProvingKey, WRAPSVerificationKey), WRAPSError> {
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

    fn dummy_ceremony_groth_setup<C: ConstraintSynthesizer<Fr>>(circuit: C)
        -> Result<(Groth16ProvingKey<PairingCurve>, Groth16VerifyingKey<PairingCurve>), WRAPSError> {
        let cs = Self::circuit_to_cs(circuit)?;
        let srs_phase1 = Self::create_init_srs_phase1(cs.clone());

        let srs_phase1 = Self::update_srs_phase1(cs.clone(), &srs_phase1);
        let srs_phase1 = Self::update_srs_phase1(cs.clone(), &srs_phase1);

        let (phase1_output, srs_phase2) = Self::specialize_srs(&srs_phase1, cs.clone());

        let srs_phase2 = Self::update_srs_phase2(&srs_phase2);
        let srs_phase2 = Self::update_srs_phase2(&srs_phase2);

        let (g16_pk, g16_vk) = Self::finish_groth_setup(
            &srs_phase1,
            &phase1_output,
            &srs_phase2,
            cs.clone()
        )?;

        Ok((g16_pk, g16_vk))
    }

    /// creates an initial SRS for Groth16, using tau = 1, and alpha, beta = 1
    fn create_init_srs_phase1(cs: ConstraintSystemRef<Fr>) -> Phase1SRS {
        // domain_size is computed the same way (and then padded to the next power of 2)
        let n = cs.num_constraints() + cs.num_instance_variables();
        let domain = GeneralEvaluationDomain::<Fr>::new(n)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge).unwrap();
        let domain_size = domain.size();

        let powers_of_tau_g1: Vec<G1Affine> = vec![G1Affine::generator(); 2*domain_size]; // {Gx:i} | i=0..2n-2}
        let powers_of_tau_g2: Vec<G2Affine> = vec![G2Affine::generator(); 2*domain_size]; // {Hx:i} | i=0..2n-2}

        let powers_of_alpha_tau_g1: Vec<G1Affine> = vec![G1Affine::generator(); domain_size]; // {Gαx:i} | i=0..n-1}
        let powers_of_alpha_tau_g2: Vec<G2Affine> = vec![G2Affine::generator(); domain_size]; // {Hαx:i} | i=0..n-1}

        let powers_of_beta_tau_g1: Vec<G1Affine> = vec![G1Affine::generator(); domain_size]; // {Gβx:i} | i=0..n-1}
        let powers_of_beta_tau_g2: Vec<G2Affine> = vec![G2Affine::generator(); domain_size]; // {Hβx:i} | i=0..n-1}

        Phase1SRS {
            powers_of_tau_g1,
            powers_of_tau_g2,
            powers_of_alpha_tau_g1,
            powers_of_alpha_tau_g2,
            powers_of_beta_tau_g1,
            powers_of_beta_tau_g2,
        }
    }

    fn update_srs_phase1(cs: ConstraintSystemRef<Fr>, prev_srs: &Phase1SRS) -> Phase1SRS {
        type D<F> = GeneralEvaluationDomain<F>;
        let n = cs.num_constraints() + cs.num_instance_variables();
        let domain = D::new(n)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge).unwrap();

        let mut rng = ark_std::rand::rngs::OsRng;
        let tau: Fr = domain.sample_element_outside_domain(&mut rng);
        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);

        // multiply all existing SRS elements by the new random scalars
        let new_powers_of_tau_g1 = prev_srs.powers_of_tau_g1
            .iter()
            .enumerate()
            .map(|(i, g)| {
                let tau_pow_i = tau.pow([i as u64]);
                g.mul(tau_pow_i).into_affine()
            })
            .collect::<Vec<G1Affine>>();

        let new_powers_of_tau_g2 = prev_srs.powers_of_tau_g2
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let tau_pow_i = tau.pow([i as u64]);
                h.mul(tau_pow_i).into_affine()
            })
            .collect::<Vec<G2Affine>>();

        let new_powers_of_alpha_tau_g1 = prev_srs.powers_of_alpha_tau_g1
            .iter()
            .enumerate()
            .map(|(i, g)| {
                let alpha_tau_pow_i = alpha * tau.pow([i as u64]);
                g.mul(alpha_tau_pow_i).into_affine()
            })
            .collect::<Vec<G1Affine>>();

        let new_powers_of_alpha_tau_g2 = prev_srs.powers_of_alpha_tau_g2
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let alpha_tau_pow_i = alpha * tau.pow([i as u64]);
                h.mul(alpha_tau_pow_i).into_affine()
            })
            .collect::<Vec<G2Affine>>();

        let new_powers_of_beta_tau_g1 = prev_srs.powers_of_beta_tau_g1
            .iter()
            .enumerate()
            .map(|(i, g)| {
                let beta_tau_pow_i = beta * tau.pow([i as u64]);
                g.mul(beta_tau_pow_i).into_affine()
            })
            .collect::<Vec<G1Affine>>();

        let new_powers_of_beta_tau_g2 = prev_srs.powers_of_beta_tau_g2
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let beta_tau_pow_i = beta * tau.pow([i as u64]);
                h.mul(beta_tau_pow_i).into_affine()
            })
            .collect::<Vec<G2Affine>>();

        Phase1SRS {
            powers_of_tau_g1: new_powers_of_tau_g1,
            powers_of_tau_g2: new_powers_of_tau_g2,
            powers_of_alpha_tau_g1: new_powers_of_alpha_tau_g1,
            powers_of_alpha_tau_g2: new_powers_of_alpha_tau_g2,
            powers_of_beta_tau_g1: new_powers_of_beta_tau_g1,
            powers_of_beta_tau_g2: new_powers_of_beta_tau_g2,
        }
    }

    fn specialize_srs(srs: &Phase1SRS, cs: ConstraintSystemRef<Fr>) -> (Phase1Output, Phase2SRS) {
        let matrices = &cs.to_matrices().unwrap()["R1CS"];
        let domain = GeneralEvaluationDomain::<Fr>::new(cs.num_constraints() + cs.num_instance_variables())
            .ok_or(SynthesisError::PolynomialDegreeTooLarge).unwrap();
        let ds = domain.size();

        let ifft_of_powers_of_tau_g1 = ECFFTUtils::ifft::<ark_bn254::G1Projective>(&srs.powers_of_tau_g1[..ds]);
        let ifft_of_powers_of_tau_g2 = ECFFTUtils::ifft::<ark_bn254::G2Projective>(&srs.powers_of_tau_g2[..ds]);
        let ifft_of_powers_of_alpha_tau_g1 = ECFFTUtils::ifft::<ark_bn254::G1Projective>(&srs.powers_of_alpha_tau_g1);
        let ifft_of_powers_of_beta_tau_g1 = ECFFTUtils::ifft::<ark_bn254::G1Projective>(&srs.powers_of_beta_tau_g1);

        let qap_num_variables = (cs.num_instance_variables() - 1) + cs.num_witness_variables();

        let mut abc_g1 = vec![G1Affine::zero(); qap_num_variables + 1];
        let mut a_g1 = vec![G1Affine::zero(); qap_num_variables + 1];
        let mut b_g1 = vec![G1Affine::zero(); qap_num_variables + 1];
        let mut b_g2 = vec![G2Affine::zero(); qap_num_variables + 1];

        // this handles the dummy constraints x * 0 = 0 for non-malleability
        {
            let start = 0;
            let end = cs.num_instance_variables();
            let num_constraints = cs.num_constraints();
            abc_g1[start..end].copy_from_slice(&ifft_of_powers_of_beta_tau_g1[(start + num_constraints)..(end + num_constraints)]);
            a_g1[start..end].copy_from_slice(&ifft_of_powers_of_tau_g1[(start + num_constraints)..(end + num_constraints)]);
        }

        for (i, u_i) in ifft_of_powers_of_beta_tau_g1.iter().enumerate().take(cs.num_constraints()) {
            for &(ref coeff, index) in &matrices[0][i] {
                abc_g1[index] = (abc_g1[index] + (*u_i * coeff)).into_affine();
            }
        }

        for (i, u_i) in ifft_of_powers_of_alpha_tau_g1.iter().enumerate().take(cs.num_constraints()) {
            for &(ref coeff, index) in &matrices[1][i] {
                abc_g1[index] = (abc_g1[index] + (*u_i * coeff)).into_affine();
            }
        }

        for (i, u_i) in ifft_of_powers_of_tau_g1.iter().enumerate().take(cs.num_constraints()) {
            for &(ref coeff, index) in &matrices[2][i] {
                abc_g1[index] = (abc_g1[index] + (*u_i * coeff)).into_affine();
            }

            for &(ref coeff, index) in &matrices[0][i] {
                a_g1[index] = (a_g1[index] + (*u_i * coeff)).into_affine();
            }

            for &(ref coeff, index) in &matrices[1][i] {
                b_g1[index] = (b_g1[index] + (*u_i * coeff)).into_affine();
            }
        }

        for (i, u_i) in ifft_of_powers_of_tau_g2.iter().enumerate().take(cs.num_constraints()) {
            for &(ref coeff, index) in &matrices[1][i] {
                b_g2[index] = (b_g2[index] + (*u_i * coeff)).into_affine();
            }
        }

        let mut h_g1 = vec![G1Affine::zero(); domain.size() - 1];
        for i in 0..=(domain.size()-2) {
            h_g1[i] = (srs.powers_of_tau_g1[i + domain.size()] - srs.powers_of_tau_g1[i]).into_affine();
        }

        // we use delta and gamma as 1 for this step
        let gamma_abc_g1 = abc_g1.clone();
        let delta_abc_g1 = abc_g1.clone();

        let delta_g1 = G1Affine::generator();
        let delta_g2 = G2Affine::generator();
        let gamma_g2 = G2Affine::generator();

        let phase1_output = Phase1Output {
            a_query: a_g1,
            b_g1_query: b_g1,
            b_g2_query: b_g2,
        };

        let phase2_srs = Phase2SRS {
            delta_g1,
            delta_g2,
            gamma_g2,
            gamma_abc_g1,
            delta_abc_g1,
            h_g1,
        };

        (phase1_output, phase2_srs)
    }

    pub fn update_srs_phase2(
        prev_srs: &Phase2SRS,
    ) -> Phase2SRS {
        let mut rng = ark_std::rand::rngs::OsRng;
        let delta = Fr::rand(&mut rng);
        let gamma = Fr::rand(&mut rng);

        let delta_inverse = delta.inverse().unwrap();
        let gamma_inverse = gamma.inverse().unwrap();

        let new_delta_g1 = prev_srs.delta_g1.mul(delta).into_affine();
        let new_delta_g2 = prev_srs.delta_g2.mul(delta).into_affine();
        let new_gamma_g2 = prev_srs.gamma_g2.mul(gamma).into_affine();
        let new_gamma_abc_g1 = prev_srs.gamma_abc_g1
            .iter()
            .map(|g| g.mul(gamma_inverse).into_affine())
            .collect::<Vec<G1Affine>>();
        let new_delta_abc_g1 = prev_srs.delta_abc_g1
            .iter()
            .map(|g| g.mul(delta_inverse).into_affine())
            .collect::<Vec<G1Affine>>();
        let new_h_g1 = prev_srs.h_g1
            .iter()
            .map(|g| g.mul(delta_inverse).into_affine())
            .collect::<Vec<G1Affine>>();

        Phase2SRS {
            delta_g1: new_delta_g1,
            delta_g2: new_delta_g2,
            gamma_g2: new_gamma_g2,
            gamma_abc_g1: new_gamma_abc_g1,
            delta_abc_g1: new_delta_abc_g1,
            h_g1: new_h_g1,
        }
    }

    pub fn finish_groth_setup(
        srs1: &Phase1SRS,
        phase1out: &Phase1Output,
        srs2: &Phase2SRS,
        cs: ConstraintSystemRef<Fr>
    ) -> Result<(Groth16ProvingKey<PairingCurve>, Groth16VerifyingKey<PairingCurve>), WRAPSError> {
        let num_instance_variables = cs.num_instance_variables();

        let g16_vk = Groth16VerifyingKey {
            alpha_g1: srs1.powers_of_alpha_tau_g1[0],
            beta_g2: srs1.powers_of_beta_tau_g2[0],
            gamma_g2: srs2.gamma_g2,
            delta_g2: srs2.delta_g2,
            gamma_abc_g1: srs2.gamma_abc_g1[..num_instance_variables].to_vec(),
        };

        let g16_pk = Groth16ProvingKey {
            vk: g16_vk.clone(),
            beta_g1: srs1.powers_of_beta_tau_g1[0],
            delta_g1: srs2.delta_g1,
            a_query: phase1out.a_query.clone(),
            b_g1_query: phase1out.b_g1_query.clone(),
            b_g2_query: phase1out.b_g2_query.clone(),
            h_query: srs2.h_g1.clone(),
            l_query: srs2.delta_abc_g1[num_instance_variables..].to_vec(),
        };

        Ok((g16_pk, g16_vk))
    }

    fn circuit_to_cs<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<ConstraintSystemRef<Fr>, WRAPSError> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit.generate_constraints(cs.clone()).map_err(|_| WRAPSError::CryptographyError)?;
        cs.finalize();
        Ok(cs)
    }
}


#[cfg(test)]
mod end_to_end_tests {
    use super::*;

    #[test]
    fn wraps_trusted_setup() {
        let (pk, vk) = WRAPSPreprocessing::trusted_setup().unwrap();
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

    const MIMC_ROUNDS: usize = 322;
    const USE_MPC_CEREMONY: bool = true;

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

    #[test]
    fn test_mimc_groth16() {
        // We're going to use the Groth16 proving system.
        use ark_groth16::Groth16;

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

            let cs = WRAPSPreprocessing::circuit_to_cs(c).unwrap();
            println!("Number of constraints: {}", cs.num_constraints());

            if USE_MPC_CEREMONY {
                WRAPSPreprocessing::dummy_ceremony_groth_setup(c).unwrap()
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