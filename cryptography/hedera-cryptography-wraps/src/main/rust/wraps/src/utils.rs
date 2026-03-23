// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::fs::File;
use std::sync::OnceLock;
use memmap2::Mmap;
use ark_bn254::{G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, Field, Zero};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_poly::{EvaluationDomain, domain::general::GeneralEvaluationDomain};
use ark_std::ops::*;
use rayon::join;

use crate::{WRAPS, ProvingKey, VerificationKey, WRAPSError};

/// Hashes an arbitrary byte slice to a G1 group element on the BN254 curve.
///
/// Uses hash-to-field (SHA-256 based) to derive a base field element, then
/// applies try-and-increment to find a valid curve point. The resulting point
/// has unknown discrete logarithm relative to the generator.
pub fn hash_to_g1(data: &[u8]) -> Result<G1Affine, WRAPSError> {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<ark_bn254::Fq>>::new(
        b"WRAPS_HASH_TO_G1_BN254",
    );
    let field_elems: [ark_bn254::Fq; 1] = hasher.hash_to_field(data);
    let mut x = field_elems[0];

    // BN254 G1: y^2 = x^3 + 3. Try successive x values until one yields
    // a quadratic residue (expected ~2 iterations on average).
    loop {
        let rhs = x * x * x + ark_bn254::Fq::from(3u64);
        if let Some(y) = rhs.sqrt() {
            return Ok(G1Affine::new_unchecked(x, y));
        }
        x += ark_bn254::Fq::ONE;
    }
}

/// Hashes an arbitrary byte slice to a G2 group element on the BN254 curve.
///
/// Uses hash-to-field (SHA-256 based) to derive two base field elements,
/// which form an Fq2 element, then applies try-and-increment to find a valid
/// curve point. The resulting point has unknown discrete logarithm relative
/// to the generator.
pub fn hash_to_g2(data: &[u8]) -> Result<G2Affine, WRAPSError> {
    use ark_ec::short_weierstrass::SWCurveConfig;

    let hasher = <DefaultFieldHasher<Sha256> as HashToField<ark_bn254::Fq>>::new(
        b"WRAPS_HASH_TO_G2_BN254",
    );
    let field_elems: [ark_bn254::Fq; 2] = hasher.hash_to_field(data);
    let mut x = ark_bn254::Fq2::new(field_elems[0], field_elems[1]);

    // BN254 G2: y^2 = x^3 + B where B is the sextic twist coefficient in Fq2.
    // Try successive x values until one yields a quadratic residue
    // (expected ~2 iterations on average).
    // BN254 G2 has a non-trivial cofactor, so after finding a curve point we
    // must clear the cofactor to land in the prime-order subgroup.
    let coeff_b = <ark_bn254::g2::Config as SWCurveConfig>::COEFF_B;
    loop {
        let rhs = x * x * x + coeff_b;
        if let Some(y) = rhs.sqrt() {
            let point = G2Affine::new_unchecked(x, y);
            return Ok(point.clear_cofactor());
        }
        x += ark_bn254::Fq2::ONE;
    }
}

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

    // For inputs smaller than FFT_PAR_CUTOFF, we perform the FFT sequentially.
    // For larger inputs, we parallelize the recursive calls.
    const FFT_PAR_CUTOFF: usize = 65536;

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

        let (y_even, y_odd) = if n > Self::FFT_PAR_CUTOFF {
            join(
                || Self::fft_recursive::<C>(&even_points, subdomain_omega),
                || Self::fft_recursive::<C>(&odd_points, subdomain_omega),
            )
        } else {
            (
                Self::fft_recursive::<C>(&even_points, subdomain_omega),
                Self::fft_recursive::<C>(&odd_points, subdomain_omega),
            )
        };

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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    #[test]
    fn test_hash_to_g1() {
        // Hash some data to G1
        let data = b"hello world";
        let point = hash_to_g1(data).unwrap();

        // The result must be a valid curve point (on-curve and in the correct subgroup)
        assert!(point.is_on_curve());
        assert!(point.is_in_correct_subgroup_assuming_on_curve());

        // Must not be the identity element
        assert!(!point.is_zero());

        // Determinism: hashing the same input twice must yield the same point
        let point2 = hash_to_g1(data).unwrap();
        assert_eq!(point, point2);

        // Different inputs must (with overwhelming probability) produce different points
        let point3 = hash_to_g1(b"different input").unwrap();
        assert_ne!(point, point3);

        // Empty input should also work
        let point4 = hash_to_g1(b"").unwrap();
        assert!(point4.is_on_curve());
        assert!(!point4.is_zero());
    }

    #[test]
    fn test_hash_to_g2() {
        // Hash some data to G2
        let data = b"hello world";
        let point = hash_to_g2(data).unwrap();

        // The result must be a valid curve point (on-curve and in the correct subgroup)
        assert!(point.is_on_curve());
        assert!(point.is_in_correct_subgroup_assuming_on_curve());

        // Must not be the identity element
        assert!(!point.is_zero());

        // Determinism: hashing the same input twice must yield the same point
        let point2 = hash_to_g2(data).unwrap();
        assert_eq!(point, point2);

        // Different inputs must (with overwhelming probability) produce different points
        let point3 = hash_to_g2(b"different input").unwrap();
        assert_ne!(point, point3);

        // Empty input should also work
        let point4 = hash_to_g2(b"").unwrap();
        assert!(point4.is_on_curve());
        assert!(!point4.is_zero());
    }
}
