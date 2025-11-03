// SPDX-License-Identifier: Apache-2.0
// Portions of this file are derived from arkworks-rs/r1cs-tutorial under Apache 2.0 License.

use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::SynthesisError;

use crate::signature::SignatureScheme;

pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;
    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;
    type SignatureVar: AllocVar<S::Signature, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

#[cfg(test)]
mod test {
    use crate::signature::{schnorr, schnorr::constraints::*, *};
    use ark_ec::CurveGroup;
    use ark_ed_on_bn254::constraints::EdwardsVar as JubJubVar;
    use ark_ed_on_bn254::EdwardsProjective as JubJub;
    use ark_ff::PrimeField;
    use ark_r1cs_std::prelude::*;
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn sign_and_verify<F: PrimeField, S: SignatureScheme, SG: SigVerifyGadget<S, F>>(
        message: &[u8],
    ) {
        let rng = &mut test_rng();
        let parameters = S::setup(rng.gen()).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng.gen()).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng.gen()).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();

        let parameters_var = SG::ParametersVar::new_constant(cs.clone(), parameters).unwrap();
        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let msg_var: Vec<_> = message
            .iter()
            .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
            .collect();
        let valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();

        valid_sig_var.enforce_equal(&Boolean::<F>::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap());
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
        type F = <JubJub as CurveGroup>::BaseField;
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<
            F,
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(message.as_bytes());
        failed_verification::<schnorr::Schnorr<JubJub>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }
}
