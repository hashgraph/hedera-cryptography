// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::fs::File;
use std::sync::OnceLock;
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

/// This env var, when set to "true", enables a cache for the ProvingKey.
/// The ProvingKey may consume ~6GB of RAM, so the caching is normally not desired because
/// the key is only used to construct AddressBook rotations proofs. However, it may be useful
/// in tests running in a single JVM (or an external dedicated JVM hosting the tss-lib) in order
/// to not waste ~27 minutes loading the key from disk and deserializing it for every proof.
const ARTIFACTS_CACHE_ENABLED_ENV_VAR: &str = "TSS_LIB_WRAPS_ARTIFACTS_CACHE_ENABLED";

/// A utility for returning the key and freeing memory if necessary.
/// An owned value will be released once the caller finishes. This is useful when the cache
/// is disabled and each call loads a new key.
/// A reference value will not be released because it's a reference to a static (cached) object.
/// The caller can call `get_ref` and obtain a reference to the value w/o having to know whether
/// the value is cached or owned.
pub struct ProvingKeyWrapper {
    owned_pk: Option<ProvingKey>,
    ref_pk: Option<&'static ProvingKey>,
}

impl ProvingKeyWrapper {
    /// Create a new owned value wrapper.
    fn new_owned(owned_pk: ProvingKey) -> Self {
        ProvingKeyWrapper {
            owned_pk: Some(owned_pk),
            ref_pk: None
        }
    }

    /// Create a new cached value wrapper.
    fn new_ref(ref_pk: &'static ProvingKey) -> Self {
        ProvingKeyWrapper {
            owned_pk: None,
            ref_pk: Some(ref_pk)
        }
    }

    /// Return a reference to the value.
    pub fn get_ref(&self) -> &ProvingKey {
        if self.ref_pk.is_some() {
            return self.ref_pk.unwrap();
        }
        if self.owned_pk.is_some() {
            return self.owned_pk.as_ref().unwrap();
        }
        // Re-iterating: this should never happen as ensured by the `new` constructors above:
        panic!("Neither ref_pk nor owned_pk exists. This should never happen!");
    }
}

/// A holder for a cached key (or empty `Option` when the cache is disabled).
static PROVING_KEY: OnceLock<Option<ProvingKey>> = OnceLock::new();

/// Loads the key from disk directly.
fn load_proving_key() -> Result<ProvingKey, WRAPSError> {
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

/// A utility getter for the cached PROVING_KEY that implements its `OnceLock` initialization.
/// Returns an empty `Option` if the cache is disabled or errors occur during loading the key.
fn get_cached_proving_key() -> &'static Option<ProvingKey> {
    PROVING_KEY.get_or_init(|| {
        let cache_enabled_str = match env::var(ARTIFACTS_CACHE_ENABLED_ENV_VAR) {
            Ok(val) => val,
            Err(_) => return None
        };

        if cache_enabled_str.to_lowercase() != "true" {
            return None;
        }

        match load_proving_key() {
            Ok(val) => Some(val),
            Err(_) => None
        }
    })
}

/// Gets a ProvingKeyWrapper. May return a cached value if the cache is enabled, or load
/// a new key otherwise. The ProvingKeyWrapper will take care of releasing memory if needed.
pub fn get_proving_key() -> Result<ProvingKeyWrapper, WRAPSError> {
    match get_cached_proving_key() {
        Some(val) => Ok(ProvingKeyWrapper::new_ref(val)),
        None => load_proving_key().map(|pk| ProvingKeyWrapper::new_owned(pk))
    }
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
