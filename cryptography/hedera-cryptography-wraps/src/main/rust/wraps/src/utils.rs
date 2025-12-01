// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::fs::File;
use memmap2::Mmap;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, Field, Zero};
use ark_poly::{EvaluationDomain, domain::general::GeneralEvaluationDomain};
use ark_std::ops::*;
use crate::{WRAPS, ProvingKey, VerificationKey, WRAPSError};

pub fn serialize<T: ark_serialize::CanonicalSerialize>(
    t: &T
) -> Vec<u8> {
    let mut buf = Vec::new();
    // unwrap() should be safe because we serialize into a variable-size vector.
    // However, it might fail if the `t` is invalid somehow, although this
    // should only occur if there is an error in the caller or this library.
    t.serialize_uncompressed(&mut buf).unwrap();
    buf
}

/**********************************************************************************************/
// Below methods retrieve Proving and Verification keys.
// In theory, a key can be cached in a static Mutex. However, it occupies up to 2GB+ of RAM, and
// it's not entirely clear if a client code would be using the key all that often to justify the
// caching of such a large data structure in memory. Again, in theory, we can add a reset_cache
// API to clear the cache. But again, it's unclear if the extra complexity is worth it.
// So for now we just load and parse the keys each time we need them in prod.
/**********************************************************************************************/

const ARTIFACTS_PATH_ENV_VAR: &str = "TSS_LIB_WRAPS_ARTIFACTS_PATH";

/// Gets a ProvingKey.
pub fn get_proving_key() -> Result<ProvingKey, WRAPSError> {
    let artifacts_path = match env::var(ARTIFACTS_PATH_ENV_VAR) {
        Ok(val) => val,
        Err(_) => return Err(WRAPSError::BinaryArtifactMissing)
    };

    let nova_pp_path = artifacts_path.clone() + "/nova_pp.bin";
    let nova_pp_map = unsafe {
        Mmap::map(&File::open(&nova_pp_path).map_err(|_| WRAPSError::BinaryArtifactMissing)?)
    }.map_err(|_| WRAPSError::BinaryArtifactMissing)?;

    let decider_pp_path = artifacts_path.clone() + "/decider_pp.bin";
    let decider_pp_map = unsafe {
        Mmap::map(&File::open(&decider_pp_path).map_err(|_| WRAPSError::BinaryArtifactMissing)?)
    }.map_err(|_| WRAPSError::BinaryArtifactMissing)?;

    WRAPS::setup_prover(nova_pp_map, decider_pp_map)
}

/// Gets a VerificationKey.
pub fn get_verification_key() -> Result<VerificationKey, WRAPSError> {
    let artifacts_path = match env::var(ARTIFACTS_PATH_ENV_VAR) {
        Ok(val) => val,
        Err(_) => return Err(WRAPSError::BinaryArtifactMissing)
    };

    let nova_vp_path = artifacts_path.clone() + "/nova_vp.bin";
    let nova_vp_map = unsafe {
        Mmap::map(&File::open(&nova_vp_path).map_err(|_| WRAPSError::BinaryArtifactMissing)?)
    }.map_err(|_| WRAPSError::BinaryArtifactMissing)?;

    let decider_vp_path = artifacts_path.clone() + "/decider_vp.bin";
    let decider_vp_map = unsafe {
        Mmap::map(&File::open(&decider_vp_path).map_err(|_| WRAPSError::BinaryArtifactMissing)?)
    }.map_err(|_| WRAPSError::BinaryArtifactMissing)?;

    WRAPS::setup_verifier(nova_vp_map, decider_vp_map)
}

/************************************************************************************/
// Methods for FFT-related operations over group elements.
/************************************************************************************/

/// Utility type for FFT-related operations on elliptic curve points.
pub struct ECFFTUtils;

impl ECFFTUtils {
    /// Computes the FFT of the given data using the Cooley-Tukey algorithm.
    pub fn fft<C: CurveGroup>(data: &[C::Affine]) -> Vec<C::Affine> {
        let n = data.len();
        assert!(n.is_power_of_two());

        type D<F> = GeneralEvaluationDomain<F>;
        let domain: D<C::ScalarField> = D::new(data.len()).unwrap();
        let omega = domain.group_gen();

        Self::fft_recursive::<C>(data, omega)
    }

    fn fft_recursive<C: CurveGroup>(data: &[C::Affine], omega: C::ScalarField) -> Vec<C::Affine> {
        let n = data.len();
        if n == 1 {
            return vec![data[0]];
        }

        // split into even and odd points
        let even_points = data
            .iter()
            .step_by(2)
            .cloned()
            .collect::<Vec<_>>();
        let odd_points = data
            .iter()
            .skip(1)
            .step_by(2)
            .cloned()
            .collect::<Vec<_>>();

        // we recurse on both halves, with omega squared
        let subdomain_omega = omega * omega;
        let y_even = Self::fft_recursive::<C>(&even_points, subdomain_omega);
        let y_odd = Self::fft_recursive::<C>(&odd_points, subdomain_omega);

        // y is the output
        let mut y = vec![C::Affine::zero(); n];
        // each iteration k will use omega^k, starting with omega^0
        let mut omega_k = C::ScalarField::from(1u64);
        for k in 0..(n / 2) {
            y[k] = (y_even[k] + (y_odd[k].mul(omega_k))).into_affine();
            y[k + n / 2] = (y_even[k] - (y_odd[k].mul(omega_k))).into_affine();
            omega_k *= &omega;
        }

        y
    }

    /// Computes the inverse FFT (IFFT) using the FFT algorithm above,
    pub fn ifft<C: CurveGroup>(data: &[C::Affine]) -> Vec<C::Affine> {
        let n = data.len();
        assert!(n.is_power_of_two());

        type D<F> = GeneralEvaluationDomain<F>;
        let domain: D<C::ScalarField> = D::new(data.len()).unwrap();
        let omega_inv = domain.group_gen().inverse().unwrap();

        let mut y = Self::fft_recursive::<C>(data, omega_inv);

        // normalize
        let n_inv = C::ScalarField::from(n as u64).inverse().unwrap();
        for i in 0..n {
            y[i] = (y[i].mul(n_inv)).into_affine();
        }
        y
    }
}


/************************************************************************************/
// Methods for FFT-related operations over scalars.
/************************************************************************************/

/// Utility type for FFT-related operations bound to a specific pairing engine.
pub struct FFTUtils;

impl FFTUtils {
    /// Computes the FFT of the given data using the Cooley-Tukey algorithm.
    pub fn fft<F: FftField> (data: &[F]) -> Vec<F> {
        let n = data.len();
        assert!(n.is_power_of_two());

        type D<F> = GeneralEvaluationDomain<F>;
        let domain: D<F> = D::new(data.len()).unwrap();
        let omega = domain.group_gen();

        Self::fft_recursive(data, omega)
    }

    /// Computes the inverse FFT (IFFT) using the FFT algorithm above,
    /// assuming the length is a power of two.
    pub fn ifft<F: FftField>(data: &[F]) -> Vec<F> {
        let n = data.len();
        assert!(n.is_power_of_two());

        type D<F> = GeneralEvaluationDomain<F>;
        let domain: D<F> = D::new(data.len()).unwrap();
        let omega_inv = domain.group_gen().inverse().unwrap();

        let mut y = Self::fft_recursive(data, omega_inv);

        // normalize
        let n_inv = F::from(n as u64).inverse().unwrap();
        for i in 0..n {
            y[i] = y[i] * n_inv;
        }
        y
    }

    fn fft_recursive<F: FftField>(data: &[F], omega: F) -> Vec<F> {
        let n = data.len();
        if n == 1 {
            return vec![data[0]];
        }

        // split into even and odd points
        let even_points = data
            .iter()
            .step_by(2)
            .cloned()
            .collect::<Vec<_>>();
        let odd_points = data
            .iter()
            .skip(1)
            .step_by(2)
            .cloned()
            .collect::<Vec<_>>();

        // we recurse on both halves, with omega squared
        let subdomain_omega = omega * omega;
        let y_even = Self::fft_recursive(&even_points, subdomain_omega);
        let y_odd = Self::fft_recursive(&odd_points, subdomain_omega);

        // y is the output
        let mut y = vec![F::zero(); n];
        // each iteration k will use omega^k, starting with omega^0
        let mut omega_k = F::from(1u64);
        for k in 0..(n / 2) {
            y[k] = y_even[k] + (omega_k * y_odd[k]);
            y[k + n / 2] = y_even[k] - (omega_k * y_odd[k]);
            omega_k *= &omega;
        }

        y
    }
}
