// SPDX-License-Identifier: Apache-2.0
// Portions of this file are derived from arkworks-rs/r1cs-tutorial under Apache 2.0 License.

use ark_serialize::{ CanonicalDeserialize, CanonicalSerialize };
use ark_std::{rand::Rng, hash::Hash};
use ark_crypto_primitives::Error;

pub mod blake2s;

pub mod constraints;
pub use constraints::*;

/// Interface to a RandomOracle
pub trait RandomOracle {
    type Output: CanonicalDeserialize + CanonicalSerialize + Clone + Eq + core::fmt::Debug + Hash + Default;
    type Parameters: Clone + Default;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;
}
