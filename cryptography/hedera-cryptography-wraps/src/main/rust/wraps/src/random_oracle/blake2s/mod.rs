// SPDX-License-Identifier: Apache-2.0
// Portions of this file are derived from arkworks-rs/r1cs-tutorial under Apache 2.0 License.

use ark_crypto_primitives::Error;
use ark_std::rand::Rng;
use digest::Digest;

use super::RandomOracle;

pub struct RO;
pub mod constraints;

impl RandomOracle for RO {
    type Parameters = ();
    type Output = [u8; 32];

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate(_: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let mut h = blake2::Blake2s256::new();
        h.update(input);
        let mut result = [0u8; 32];
        result.copy_from_slice(&h.finalize());
        Ok(result)
    }
}
