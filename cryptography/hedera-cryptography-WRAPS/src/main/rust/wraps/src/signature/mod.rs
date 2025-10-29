// SPDX-License-Identifier: Apache-2.0
// Portions of this file are derived from arkworks-rs/r1cs-tutorial under Apache 2.0 License.

use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod schnorr;
pub mod constraints;
pub use constraints::*;


pub trait SignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + CanonicalDeserialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + CanonicalDeserialize + Clone + Default;
    type Signature: CanonicalSerialize + CanonicalDeserialize + Clone + Default + Send + Sync;

    fn setup(
        entropy: [u8; 32]
    ) -> Result<Self::Parameters, Error>;

    fn keygen(
        pp: &Self::Parameters,
        entropy: [u8; 32],
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        entropy: [u8; 32],
    ) -> Result<Self::Signature, Error>;

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod test {
    use crate::signature::{schnorr, *};
    use ark_ed_on_bn254::EdwardsProjective as JubJub;
    use ark_std::test_rng;

    fn sign_and_verify<S: SignatureScheme>(message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = S::setup(rng.gen()).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng.gen()).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng.gen()).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());
    }

    fn failed_verification<S: SignatureScheme>(message: &[u8], bad_message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = S::setup(rng.gen()).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng.gen()).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng.gen()).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }

    #[test]
    fn schnorr_signature_test() {
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<schnorr::Schnorr<JubJub>>(message.as_bytes());
        failed_verification::<schnorr::Schnorr<JubJub>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }
}
