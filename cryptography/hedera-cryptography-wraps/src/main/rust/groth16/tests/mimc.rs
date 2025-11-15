#![warn(unused)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    unsafe_code
)]

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
// For randomness (during paramgen and proof generation)
use ark_std::rand::{Rng, RngCore, SeedableRng};

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use ark_bls12_377::{Bls12_377, Fr};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
};
use ark_std::test_rng;

// We'll use these interfaces to construct our circuit.
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

const MIMC_ROUNDS: usize = 322;

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

        Groth16::<Bls12_377>::setup(c, &mut rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = Groth16::<Bls12_377>::process_vk(&vk).unwrap();

    println!("Creating proofs...");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 50;
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
            let proof = Groth16::<Bls12_377>::prove(&pk, c, &mut rng).unwrap();
            assert!(
                Groth16::<Bls12_377>::verify_with_processed_vk(&pvk, &[image], &proof).unwrap()
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
