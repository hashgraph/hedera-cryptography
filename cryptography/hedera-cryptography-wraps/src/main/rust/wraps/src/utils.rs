// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::fs::File;
use memmap2::Mmap;
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