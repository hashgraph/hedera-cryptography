// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(unused_imports)]
#![allow(dead_code)]

mod signature;
mod random_oracle;
mod utils;
mod jni_util;
mod jni_wraps;
mod alloc;
pub mod preprocessing;

use signature::{*};

/********************************* Imports *********************************/

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    uint::UInt,
    GR1CSVar
};
use ark_snark::SNARK;
use ark_crypto_primitives::crh::{
    sha256::Sha256,
    poseidon::constraints::{CRHGadget as PoseidonCRHGadget, CRHParametersVar as PoseidonCRHParametersVar},
    poseidon::CRH as PoseidonCRH,
    CRHSchemeGadget, CRHScheme
};
use ark_groth16::{Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, test_rng, rand::thread_rng, fmt::Debug};
use ark_poly::{GeneralEvaluationDomain, EvaluationDomain};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
    OptimizationGoal, Result as R1CSResult,
    SynthesisError, SynthesisMode, Namespace
};

use core::borrow::Borrow;
use core::{marker::PhantomData};
use std::ops::{Add, AddAssign};

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
use folding_schemes::folding::nova::decider_eth_circuit::DeciderEthCircuit;
use folding_schemes::folding::traits::Dummy;

/********************************* Publicly Exposed Types *********************************/

/// Error enum to wrap underlying failures in RAPS operations,
/// or wrap errors coming from dependencies (namely, arkworks).
#[derive(Debug)]
pub enum WRAPSError {
    /// Multi-purpose error type for describing invalid inputs
    InvalidInput(String),
    /// Multi-purpose error type for describing prover failure
    CryptographyError,
    /// Error indicating address book size exceeded maximum allowed
    AddressBookSizeExceeded,
    /// TSS_LIB_WRAPS_ARTIFACTS_PATH is undefined or artifacts are unreadable
    BinaryArtifactMissing
}

/// Phases of the signing protocol: 3 rounds followed by aggregation
#[derive(Clone, Debug)]
pub enum SigningProtocolPhase {
    R1 = 1,
    R2 = 2,
    R3 = 3,
    Aggregate = 4,
}

pub type SigningProtocolMessage = Vec<u8>;

pub enum SigningProtocolObject {
    ProtocolMessage(SigningProtocolMessage),
    ProtocolOutput(SchnorrSignature),
}

pub type CompressedProofSerialized = Vec<u8>;
pub type UncompressedProofSerialized = Vec<u8>;

pub type UncompressedProvingKeySerialized = Vec<u8>;
pub type CompressedProvingKeySerialized = Vec<u8>;
pub type UncompressedVerificationKeySerialized = Vec<u8>;
pub type CompressedVerificationKeySerialized = Vec<u8>;

pub type UncompressedProvingKey = NPP;
pub type CompressedProvingKey = DPP;
pub type UncompressedVerificationKey = NVP;
pub type CompressedVerificationKey = DVP;

pub struct ProvingKey {
    pub nova_pp: UncompressedProvingKey,
    pub decider_pp: CompressedProvingKey,
}

pub struct VerificationKey {
    pub nova_vp: UncompressedVerificationKey,
    pub decider_vp: CompressedVerificationKey,
}

/********************************* Parameters *********************************/

pub const ENTROPY_SIZE: usize = 32; // size of the seed for key generation

/********************************* Configurable Types *********************************/

/// We can only support address books up to this size.
const MAX_AB_SIZE: usize = 128;

type PairingCurve = ark_bn254::Bn254;
type G1 = ark_bn254::G1Projective;
type G2 = ark_grumpkin::Projective;
type Fr = ark_bn254::Fr;
type JubJubFr = ark_ed_on_bn254::Fr;
type JubJub = ark_ed_on_bn254::EdwardsProjective;
type JubJubVar = ark_ed_on_bn254::constraints::EdwardsVar;

/********************************* Derived Types *********************************/

const MAX_EXT_INPUTS: usize = 4 * MAX_AB_SIZE + 4;

type Schnorr = signature::schnorr::Schnorr<JubJub>;
type SchnorrSignature = <Schnorr as SignatureScheme>::Signature;
type SchnorrPrivKey = JubJubFr;
type SchnorrPubKey = <JubJub as CurveGroup>::Affine;
type SchnorrParams = signature::schnorr::Parameters<JubJub>;

type SchnorrPubKeyVar = signature::schnorr::constraints::PublicKeyVar<JubJub, JubJubVar>;
type SchnorrSignatureVar = signature::schnorr::constraints::SignatureVar<JubJub, JubJubVar>;
type SchnorrVerifyGadget = signature::schnorr::constraints::SchnorrSignatureVerifyGadget<JubJub, JubJubVar>;

type ThresholdSchnorr = signature::schnorr::ThresholdSchnorr<JubJub>;
type ThresholdSchnorrR1Msg = signature::schnorr::ThresholdSchnorrMessage1;
type ThresholdSchnorrR2Msg = signature::schnorr::ThresholdSchnorrMessage2<JubJub>;
type ThresholdSchnorrR3Msg = signature::schnorr::ThresholdSchnorrMessage3<JubJub>;

type GrothProverKey = <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::ProvingKey;
type GrothVerifierKey = <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::VerifyingKey;

type Weight = Fr;
type AddressBookHash = Fr;
type TSSVKHash = Fr;
type AddressBookEntry = (SchnorrPubKey, Weight);
type AddressBook = Vec<AddressBookEntry>;
type Keys = Vec<SchnorrPrivKey>;

type Circuit = TSSFCircuit<MAX_AB_SIZE>;
type N = Nova<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NovaProof = <N as FoldingScheme<G1, G2, Circuit>>::IVCProof;
type NPP = ProverParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NVP = VerifierParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type D = DeciderEth<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, Groth16<PairingCurve>, N>;
type DPP = (GrothProverKey, <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::ProverParams);
type DVP = VerifierParam<G1, <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::VerifierParams, GrothVerifierKey>;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct ProofData {
    pub i: Fr,
    pub z_0: Vec<Fr>,
    pub z_i: Vec<Fr>,
    pub U_i_commitments: Vec<G1>,
    pub u_i_commitments: Vec<G1>,
    pub proof: EthProof<G1, KZG<'static, PairingCurve>, Groth16<PairingCurve>>,
}

/********************************* Custom GlobalAlloc *********************************/
#[global_allocator]
static ALLOCATOR: crate::alloc::MemmapAllocator = crate::alloc::MemmapAllocator::new();

/********************************* Useful Definitions *********************************/

#[derive(Clone, Debug)]
pub struct VecF<F: PrimeField, const L: usize>(pub Vec<F>);
impl<F: PrimeField, const L: usize> Default for VecF<F, L> {
    fn default() -> Self {
        VecF(vec![F::zero(); L])
    }
}

#[derive(Clone, Debug)]
pub struct VecFpVar<F: PrimeField, const L: usize>(pub Vec<FpVar<F>>);
impl<F: PrimeField, const L: usize> AllocVar<VecF<F, L>, F> for VecFpVar<F, L> {
    fn new_variable<T: Borrow<VecF<F, L>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let v = Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(val.borrow().0.clone()), mode)?;

            Ok(VecFpVar(v))
        })
    }
}

impl<F: PrimeField, const L: usize> Default for VecFpVar<F, L> {
    fn default() -> Self {
        VecFpVar(vec![FpVar::<F>::Constant(F::zero()); L])
    }
}


/********************************* Circuit *********************************/

#[derive(Clone, Copy, Debug)]
pub struct TSSFCircuit<const K: usize>;

impl<const K: usize> FCircuit<Fr> for TSSFCircuit<K> {
    type Params = ();
    type ExternalInputs = VecF<Fr, MAX_EXT_INPUTS>;
    type ExternalInputsVar = VecFpVar<Fr, MAX_EXT_INPUTS>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        // This circuit has no tunable parameters; return the unit struct.
        Ok(Self { })
    }

    fn state_len(&self) -> usize {
        // The folding state tracks the current address-book hash and hints hash.
        2
    }

    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {

        let prev_pk_vars = (0..K)
            .map(|i| JubJubVar::new_witness(cs.clone(), || Ok(
                ark_ed_on_bn254::EdwardsAffine::new(
                    external_inputs.0[3*i + 0].value()?,
                    external_inputs.0[3*i + 1].value()?
                )
            )).unwrap())
            .collect::<Vec<_>>();

        let prev_weights = (0..K)
            .map(|i| external_inputs.0[3*i + 2].clone())
            .collect::<Vec<_>>();

        let present_bits = (0..K)
            .map(|i| external_inputs.0[3*K + i].to_bytes_le().unwrap()[0].clone())
            .collect::<Vec<_>>();

        let aggregate_signature = SchnorrSignatureVar {
            verifier_challenge: external_inputs.0[4*K + 0].to_bytes_le().unwrap(),
            prover_response: external_inputs.0[4*K + 1].to_bytes_le().unwrap(),
            _group: PhantomData,
        };

        // compute aggregate public key and aggregate weight from the bitvector
        let zero_weight = FpVar::<Fr>::new_witness(
            cs.clone(), || Ok(Fr::from(0))
        )?;
        let zero_jubjub_element = JubJubVar::new_witness(
            cs.clone(), || Ok(ark_ed_on_bn254::EdwardsAffine::zero())
        )?;
        let mut aggregate_weight = FpVar::<Fr>::new_witness(
            cs.clone(), || Ok(Fr::from(0))
        )?;
        let mut total_weight = FpVar::<Fr>::new_witness(
            cs.clone(), || Ok(Fr::from(0))
        )?;
        let mut aggregate_pubkey = JubJubVar::new_witness(
            cs.clone(), || Ok(ark_ed_on_bn254::EdwardsAffine::zero())
        )?;
        for i in 0..K {
            let is_present = present_bits[i].is_eq(&UInt::constant(1))?;

            // If the i-th bit is set, add the corresponding public key and weight to the aggregate.
            aggregate_pubkey.add_assign(&is_present.select(&prev_pk_vars[i], &zero_jubjub_element)?);
            aggregate_weight.add_assign(is_present.select(&prev_weights[i], &zero_weight)?);
            total_weight.add_assign(&prev_weights[i]);
        }

        // Schnorr gadget expects a schnorr pub key var,
        // so let's create one from the computed aggregate pubkey
        let aggregate_schnorr_pubkey_var = SchnorrPubKeyVar {
            pub_key: aggregate_pubkey.clone(),
            _group: PhantomData,
        };

        // Enforce constraints between the witness values and the circuit variables
        aggregate_pubkey.x.enforce_equal(&aggregate_schnorr_pubkey_var.pub_key.x)?;
        aggregate_pubkey.y.enforce_equal(&aggregate_schnorr_pubkey_var.pub_key.y)?;

        // Enforce that the aggregate weight is less than half the total weight.
        let two_times_aggregate_weight = &aggregate_weight + &aggregate_weight;
        total_weight.enforce_cmp(&two_times_aggregate_weight, std::cmp::Ordering::Less, false)?;

        let poseidon_config_var = PoseidonCRHParametersVar::new_constant(
            cs.clone(), poseidon_canonical_config::<Fr>()
        )?;
        let recomputed_prev_state = {
            // Recreate the Poseidon hash that committed the previous address book.
            let x_coords: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*i].clone())
                .collect();
            let y_coords: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*i + 1].clone())
                .collect();
            let weights: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*i + 2].clone())
                .collect();
            let poseidon_input: Vec<FpVar<Fr>> = x_coords
                .into_iter()
                .chain(y_coords.into_iter())
                .chain(weights.into_iter())
                .collect();
            let poseidon_output = PoseidonCRHGadget::evaluate(&poseidon_config_var, &poseidon_input)?;
            poseidon_output.to_constraint_field()?
        };

        // instantiate the Schnorr signature verification gadget
        let schnorr_parameters = Schnorr::setup(test_rng().gen()).unwrap();
        let parameters_var = <SchnorrVerifyGadget as SigVerifyGadget<Schnorr, Fr>>
            ::ParametersVar::new_constant(cs.clone(), schnorr_parameters)?;
        let next_ab_hash = external_inputs.0[4*K + 2].clone();
        let tss_vk_hash = external_inputs.0[4*K + 3].clone();
        let msg_var = next_ab_hash
            .to_bytes_le()?
            .into_iter()
            .chain(tss_vk_hash.to_bytes_le()?)
            .collect::<Vec<_>>();
        let valid_sig_var = <SchnorrVerifyGadget as SigVerifyGadget<Schnorr, Fr>>::verify(
            &parameters_var,
            &aggregate_schnorr_pubkey_var,
            &msg_var,
            &aggregate_signature
        )?;
        // enforce that the signature is valid
        valid_sig_var.enforce_equal(&Boolean::<Fr>::TRUE)?;

        // enforce that the previous public keys are equal to the external inputs
        for i in 0..K {
            prev_pk_vars[i].x.enforce_equal(&external_inputs.0[3*i + 0])?;
            prev_pk_vars[i].y.enforce_equal(&external_inputs.0[3*i + 1])?;
        }

        // enforce that the recomputed previous address book hash
        // is equal to the external input from the last step
        recomputed_prev_state[0].enforce_equal(&z_i[0])?;

        Ok(vec![next_ab_hash, tss_vk_hash])
    }
}

/// Pads an address book up to `MAX_AB_SIZE` using dummy zero-weight entries.
fn pad_addressbook(ab: &AddressBook) -> AddressBook {
    let mut ab_padded = ab.clone();
    let dummy_party = WRAPS::keygen([0; 32]).unwrap();
    let zero_weight = Fr::from(0);
    while ab_padded.len() < MAX_AB_SIZE {
        ab_padded.push((dummy_party.1.clone(), zero_weight));
    }
    ab_padded
}

/// Hashes the serialized TSS verification key using Poseidon.
pub fn hash_hints_vk(vk_bytes: &[u8]) -> Result<Fr, WRAPSError> {
    let mut tss_vk_hash_elements = Vec::new();
    let mut i = 0;
    while i < vk_bytes.len() {
        let start= i;
        let end = std::cmp::min(i + 32, vk_bytes.len());
        tss_vk_hash_elements.push(Fr::from_le_bytes_mod_order(&vk_bytes[start..end]));
        i += 32;
    }

    let out_bytes = PoseidonCRH::evaluate(&poseidon_canonical_config::<Fr>(), tss_vk_hash_elements)
        .map_err(|_| WRAPSError::CryptographyError)?;
    let out: Vec<Fr> = out_bytes.to_field_elements().unwrap();
    // because of modulus, we actually get two Fr elemeents, but we will only use the first one
    Ok(out[0])
}

/// Hashes all address book public keys and weights via Poseidon.
fn hash_addressbook(ab: &AddressBook) -> Result<Fr, WRAPSError> {
    let xcoords: Vec<Fr> = ab
        .iter()
        .map(|abe| abe.0.x)
        .collect();
    let ycoords: Vec<Fr> = ab
        .iter()
        .map(|abe| abe.0.y)
        .collect();
    let weights: Vec<Fr> = ab
        .iter()
        .map(|abe| abe.1)
        .collect();
    let poseidon_input: Vec<Fr> = xcoords.into_iter()
        .chain(ycoords.into_iter())
        .chain(weights.into_iter())
        .collect();
    let out_bytes = PoseidonCRH::evaluate(&poseidon_canonical_config::<Fr>(), poseidon_input)
        .map_err(|_| WRAPSError::CryptographyError)?;
    let out: Vec<Fr> = out_bytes.to_field_elements().unwrap();
    // because of modulus, we actually get two Fr elemeents, but we will only use the first one
    Ok(out[0])
}

/// Formats user-visible data into the external-input vector consumed by the Nova circuit.
fn prepare_external_inputs(
    aggregate_signature: &SchnorrSignature,
    prev_ab: &AddressBook,
    next_ab: &AddressBook,
    next_hints_vk: &[u8],
    bitvector: &[bool; MAX_AB_SIZE],
) -> Result<Vec<Fr>, WRAPSError> {
    // assumes prev_ab and next_ab are already padded to MAX_AB_SIZE
    if prev_ab.len() != MAX_AB_SIZE || next_ab.len() != MAX_AB_SIZE {
        return Err(WRAPSError::InvalidInput(
            "prepare_external_inputs expected padded AddressBooks".to_string()
        ));
    }

    // assumes padded bitvector of size MAX_AB_SIZE
    if bitvector.len() != MAX_AB_SIZE {
        return Err(WRAPSError::InvalidInput(
            "prepare_external_inputs expected padded bitvector".to_string()
        ));
    }

    let mut external_inputs_at_step = Vec::new();
    for i in 0..MAX_AB_SIZE {
        external_inputs_at_step.push(prev_ab[i].0.x);
        external_inputs_at_step.push(prev_ab[i].0.y);
        external_inputs_at_step.push(prev_ab[i].1);
    }

    for i in 0..MAX_AB_SIZE {
        external_inputs_at_step.push(Fr::from(bitvector[i])); // even signatures present
    }

    let verifier_challenge = Fr::from_le_bytes_mod_order(
        &aggregate_signature.verifier_challenge.into_bigint().to_bytes_le());
    let prover_response = Fr::from_le_bytes_mod_order(
        &aggregate_signature.prover_response.into_bigint().to_bytes_le());
    external_inputs_at_step.push(verifier_challenge);
    external_inputs_at_step.push(prover_response);

    external_inputs_at_step.push(hash_addressbook(&next_ab)?);
    external_inputs_at_step.push(hash_hints_vk(next_hints_vk)?);

    Ok(external_inputs_at_step)
}


impl ProvingKey {
    /// Recreates a proving key from serialized Nova and decider artifacts.
    pub fn deserialize(nova_pp: impl AsRef<[u8]>, decider_pp: impl AsRef<[u8]>) -> Result<Self, Error> {
        let nova_pp: NPP = N::pp_deserialize_with_mode(
            nova_pp.as_ref(),
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes,
            ()
        )?;
        let decider_pp = DPP::deserialize_compressed(decider_pp.as_ref())?;
        Ok(Self { nova_pp, decider_pp })
    }

    /// Serializes both Nova and decider proving parameters.
    pub fn serialize(&self) -> Result<(UncompressedProvingKeySerialized, CompressedProvingKeySerialized), Error> {
        let mut nova_pp_serialized: UncompressedProvingKeySerialized = vec![];
        self.nova_pp.serialize_compressed(&mut nova_pp_serialized)?;

        let mut decider_pp_serialized: CompressedProvingKeySerialized = vec![];
        self.decider_pp.serialize_compressed(&mut decider_pp_serialized)?;
        Ok((nova_pp_serialized, decider_pp_serialized))
    }
}

impl VerificationKey {
    /// Recreates a verification key from serialized Nova and decider artifacts.
    pub fn deserialize(nova_vp: impl AsRef<[u8]>, decider_vp: impl AsRef<[u8]>) -> Result<Self, Error> {
        let nova_vp: NVP = N::vp_deserialize_with_mode(nova_vp.as_ref(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
        let decider_vp = DVP::deserialize_compressed(decider_vp.as_ref())?;
        Ok(Self { nova_vp, decider_vp })
    }

    /// Serializes both Nova and decider verifier parameters.
    pub fn serialize(&self) -> Result<(UncompressedVerificationKeySerialized, CompressedVerificationKeySerialized), Error> {
        let mut nova_vp_serialized: UncompressedVerificationKeySerialized = vec![];
        self.nova_vp.serialize_compressed(&mut nova_vp_serialized)?;

        let mut decider_vp_serialized: CompressedVerificationKeySerialized = vec![];
        self.decider_vp.serialize_compressed(&mut decider_vp_serialized)?;
        Ok((nova_vp_serialized, decider_vp_serialized))
    }
}

impl std::error::Error for WRAPSError {}

impl std::fmt::Display for WRAPSError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            WRAPSError::InvalidInput(ref s) => write!(f, "Invalid input: {s}"),
            WRAPSError::CryptographyError => write!(f, "CryptographyError error"),
            WRAPSError::AddressBookSizeExceeded => write!(f, "Address book size exceeded maximum allowed"),
            WRAPSError::BinaryArtifactMissing => write!(f, "TSS_LIB_WRAPS_ARTIFACTS_PATH is undefined or the binary artifacts are missing"),
        }
    }
}

pub struct WRAPS {}

impl WRAPS {

    /// Derives a Schnorr keypair deterministically from the provided entropy.
    ///
    /// # Arguments
    /// * `seed` - 32-byte entropy used to sample the private key deterministically.
    ///
    /// # Returns
    /// * `Ok((sk, pk))` containing the Schnorr secret and public keys.
    /// * `Err(WRAPSError::CryptographyError)` if parameter generation or key derivation fails.
    pub fn keygen(
        seed: [u8; ENTROPY_SIZE]
    ) -> Result<(SchnorrPrivKey, SchnorrPubKey), WRAPSError> {
        // Initialize Schnorr parameters deterministically for reproducible keygen.
        // secret is a random scalar x, and the pubkey is y = xG
        let pp = Schnorr::setup([0u8; 32])
            .map_err(|_| WRAPSError::CryptographyError)?;
        // Derive the keypair from the supplied seed.
        let (pk, sk) = Schnorr::keygen(&pp, seed)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok((sk, pk))
    }

    /// Executes a single phase of the threshold Schnorr signing protocol.
    ///
    /// # Arguments
    /// * `phase` - Which protocol phase to execute (R1, R2, R3, or Aggregate).
    /// * `protocol_instance_entropy` - Participant-specific randomness reused across rounds.
    /// * `message_to_sign` - Byte message that rounds R3/Aggregate must attest.
    /// * `signing_key` - Optional private key required only during phase R3.
    /// * `public_keys` - Participants' public keys; must be present for phases beyond R1.
    /// * `round1_messages` / `round2_messages` / `round3_messages` - Messages collected from prior rounds.
    ///
    /// # Returns
    /// * `Ok(SigningProtocolObject::ProtocolMessage(_))` for R1–R3 containing the serialized round output.
    /// * `Ok(SigningProtocolObject::ProtocolOutput(_))` for Aggregate containing the final Schnorr signature.
    /// * `Err(WRAPSError::CryptographyError)` if Schnorr operations fail.
    pub fn signing_protocol(
        phase: SigningProtocolPhase, // either R1, R2, R3, or Aggregate
        protocol_instance_entropy: Option<[u8; ENTROPY_SIZE]>, // reuse in all rounds of a protocol instance R1...R3, and pass empty in Aggregate
        message_to_sign: impl AsRef<[u8]>, // message to sign should be output of rotation_message(..)
        signing_key: Option<&SchnorrPrivKey>, // should be None if phase == Aggregate
        public_keys: &[SchnorrPubKey], // can be [] if phase == R1, but must be non-empty otherwise
        round1_messages: &[SigningProtocolMessage], // should be [] if phase == R1
        round2_messages: &[SigningProtocolMessage], // should be [] if phase == R2
        round3_messages: &[SigningProtocolMessage], // should be [] if phase == R3
    ) -> Result<SigningProtocolObject, WRAPSError> {
        // Use fixed parameters so every participant derives identical protocol randomness.
        let pp = Schnorr::setup([0u8; 32]).unwrap(); // dummy entropy for dummy parameters

        match phase {
            SigningProtocolPhase::R1 => {
                // Round 1 only needs fresh commitments, no prior messages expected.
                assert!(round1_messages.len() == 0);
                assert!(round2_messages.len() == 0);
                assert!(round3_messages.len() == 0);
                assert!(protocol_instance_entropy.is_some());
                let r1_msg: ThresholdSchnorrR1Msg = ThresholdSchnorr::sign_round1(
                    &pp,
                    protocol_instance_entropy.unwrap()
                ).map_err(|_| WRAPSError::CryptographyError)?;
                let r1_msg_encoded = utils::serialize(&r1_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r1_msg_encoded))
            },
            SigningProtocolPhase::R2 => {
                // Round 2 produces each signer's commitments; all R1 messages must be present.
                assert!(round1_messages.len() == public_keys.len());
                assert!(round2_messages.len() == 0);
                assert!(round3_messages.len() == 0);
                assert!(protocol_instance_entropy.is_some());
                let r1_msgs: Vec<ThresholdSchnorrR1Msg> = round1_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR1Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r2_msg: ThresholdSchnorrR2Msg = ThresholdSchnorr::sign_round2(
                    &pp,
                    protocol_instance_entropy.unwrap(),
                    &r1_msgs
                ).map_err(|_| WRAPSError::CryptographyError)?;
                // Encode the second-round commitments to broadcast to the committee.
                let r2_msg_encoded = utils::serialize(&r2_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r2_msg_encoded))
            },
            SigningProtocolPhase::R3 => {
                // Round 3 produces each signer’s response; all prior messages must be present.
                assert!(round1_messages.len() == public_keys.len());
                assert!(round2_messages.len() == public_keys.len());
                assert!(round3_messages.len() == 0);
                assert!(protocol_instance_entropy.is_some());
                let r1_msgs: Vec<ThresholdSchnorrR1Msg> = round1_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR1Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r2_msgs: Vec<ThresholdSchnorrR2Msg> = round2_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR2Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r3_msg = ThresholdSchnorr::sign_round3(
                    &pp,
                    protocol_instance_entropy.unwrap(),
                    message_to_sign.as_ref(),
                    signing_key.unwrap(),
                    public_keys,
                    &r1_msgs,
                    &r2_msgs
                ).map_err(|_| WRAPSError::CryptographyError)?;
                // Return the serialized round-3 share to be gathered by the aggregator.
                let r3_msg_encoded = utils::serialize(&r3_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r3_msg_encoded))
            },
            SigningProtocolPhase::Aggregate => {
                // Aggregator verifies inputs and bundles all shares into a final signature.
                assert!(round1_messages.len() == public_keys.len());
                assert!(round2_messages.len() == public_keys.len());
                assert!(round3_messages.len() == public_keys.len());
                assert!(protocol_instance_entropy.is_none());
                let r1_msgs: Vec<ThresholdSchnorrR1Msg> = round1_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR1Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r2_msgs: Vec<ThresholdSchnorrR2Msg> = round2_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR2Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r3_msgs: Vec<ThresholdSchnorrR3Msg> = round3_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR3Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let signature = ThresholdSchnorr::aggregate(
                    &pp,
                    message_to_sign.as_ref(),
                    public_keys,
                    &r1_msgs,
                    &r2_msgs,
                    &r3_msgs,
                ).map_err(|_| WRAPSError::CryptographyError)?;
                Ok(SigningProtocolObject::ProtocolOutput(signature))
            },
        }
    }

    /// Verifies an aggregated Schnorr signature against the supplied public keys.
    ///
    /// # Arguments
    /// * `public_keys` - Subset of participant public keys who collectively signed the message.
    /// * `message` - Message bytes that were signed.
    /// * `signature` - Aggregated Schnorr signature to validate.
    ///
    /// # Returns
    /// * `Ok(true)` when the signature verifies successfully.
    /// * `Ok(false)` when the signature is invalid.
    /// * `Err(WRAPSError::CryptographyError)` when verification cannot be performed.
    pub fn verify_signature(
        public_keys: &[SchnorrPubKey],
        message: impl AsRef<[u8]>,
        signature: &SchnorrSignature
    ) -> Result<bool, WRAPSError> {
        // dummy entropy [0u8; 32] for dummy parameters, since we don't need salting here
        let pp = Schnorr::setup([0u8; 32]).unwrap();
        // Aggregate the provided public keys to obtain the threshold public key.
        let aggregate_pk = public_keys
            .iter()
            .fold(SchnorrPubKey::zero(), |acc, pk| (acc + pk).into_affine());
        // Verify the combined signature against the aggregate key and message.
        Schnorr::verify(&pp, &aggregate_pk, message.as_ref(), signature)
            .map_err(|_| WRAPSError::CryptographyError)
    }

    /// Computes the Poseidon hash of an address book.
    /// This is expected to only be used to compute the ledger ID.
    ///
    /// # Arguments
    /// * `ab` - Address book entries whose hash is needed; length must not exceed `MAX_AB_SIZE`.
    ///
    /// # Returns
    /// * `Ok(AddressBookHash)` containing the Poseidon digest of the padded address book.
    /// * `Err(WRAPSError::AddressBookSizeExceeded)` if the address book is too large.
    /// * `Err(WRAPSError::CryptographyError)` if hashing fails.
    pub fn compute_addressbook_hash(
        ab: &AddressBook
    ) -> Result<AddressBookHash, WRAPSError> {
        if ab.len() > MAX_AB_SIZE {
            return Err(WRAPSError::AddressBookSizeExceeded);
        }
        // Pad the address book to the circuit’s expected length before hashing.
        let padded_ab = pad_addressbook(ab);

        hash_addressbook(&padded_ab)
    }

    /// Builds the message that signers attest to when rotating an address book.
    ///
    /// # Arguments
    /// * `ab_next` - Next address book state being proposed.
    /// * `tss_vk` - Serialized threshold-verification key that corresponds to `ab_next`.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` containing the concatenation of the address book hash and the hashed verification key.
    /// * `Err(WRAPSError::AddressBookSizeExceeded)` if `ab_next` exceeds `MAX_AB_SIZE`.
    /// * `Err(WRAPSError::CryptographyError)` if hashing fails.
    pub fn compute_rotation_message(
        ab_next: &AddressBook,
        hints_vk: impl AsRef<[u8]>
    ) -> Result<Vec<u8>, WRAPSError> {
        if ab_next.len() > MAX_AB_SIZE {
            return Err(WRAPSError::AddressBookSizeExceeded);
        }
        // Normalize the next address book to the fixed circuit width.
        let padded_ab_next = pad_addressbook(ab_next);

        // Concatenate the address book hash and hashed TSS verification key to form the message.
        let msg = [
            hash_addressbook(&padded_ab_next)?.into_bigint().to_bytes_le(),
            hash_hints_vk(hints_vk.as_ref())?.into_bigint().to_bytes_le()
        ].concat();
        Ok(msg)
    }

    /// Reconstructs a proving key from serialized Nova and decider parameters.
    ///
    /// # Arguments
    /// * `nova_pp` - Byte slice containing Nova prover parameters.
    /// * `decider_pp` - Byte slice containing decider prover parameters.
    ///
    /// # Returns
    /// * `Ok(ProvingKey)` ready for WRAPS proof construction.
    /// * `Err(WRAPSError::CryptographyError)` if deserialization fails.
    pub fn setup_prover(
        nova_pp: impl AsRef<[u8]>,
        decider_pp: impl AsRef<[u8]>,
    ) -> Result<ProvingKey, WRAPSError> {
        // Deserialize both Nova and decider proving artifacts from disk-ready bytes.
        let pk = ProvingKey::deserialize(nova_pp, decider_pp)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok(pk)
    }

    /// Reconstructs a verification key from serialized Nova and decider parameters.
    ///
    /// # Arguments
    /// * `nova_vp` - Byte slice with Nova verifier parameters.
    /// * `decider_vp` - Byte slice with decider verifier parameters.
    ///
    /// # Returns
    /// * `Ok(VerificationKey)` suitable for WRAPS proof verification.
    /// * `Err(WRAPSError::CryptographyError)` if deserialization fails.
    pub fn setup_verifier(
        nova_vp: impl AsRef<[u8]>,
        decider_vp: impl AsRef<[u8]>,
    ) -> Result<VerificationKey, WRAPSError> {
        // Deserialize the verification artifacts for Nova and the decider.
        let vk = VerificationKey::deserialize(nova_vp, decider_vp)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok(vk)
    }

    /// Serializes the decider portion of a verification key into compressed bytes.
    ///
    /// # Arguments
    /// * `vk` - Verification key whose decider verifier parameters will be compressed.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` holding the compressed decider verifier parameters.
    /// * `Err(WRAPSError::CryptographyError)` if serialization fails.
    pub fn get_compressed_verification_key_bytes(
        vk: &VerificationKey
    ) -> Result<CompressedVerificationKeySerialized, WRAPSError> {
        let mut decider_vp_serialized = vec![];
        // Store only the decider verifier parameters; Nova verifier data stays uncompressed elsewhere.
        vk.decider_vp.serialize_compressed(&mut decider_vp_serialized)
            .map_err(|_| WRAPSError::CryptographyError)?;

        Ok(decider_vp_serialized)
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates the first proof for the genesis AddressBook.
    /// Produces both the incremental Nova proof and the compressed decider proof.
    ///
    /// # Arguments
    /// * `pk` - Proving key returned by [`setup_prover`].
    /// * `vk` - Verification key returned by [`setup_verifier`].
    /// * `ab_genesis_hash` - Expected hash of the genesis address book for consistency checks.
    /// * `prev_ab` - Current address book snapshot.
    /// * `next_ab` - Next address book snapshot authorized by the committee.
    /// * `prev_proof` - Optional uncompressed Nova proof from the previous iteration.
    /// * `tss_vk` - Serialized threshold verification key corresponding to `next_ab`.
    /// * `aggregate_signature` - Aggregated Schnorr signature validating the rotation message.
    /// * `bitvector` - Participation bitmap indicating which parties signed.
    ///
    /// # Returns
    /// * `Ok((uncompressed_ivc, compressed_decider))` where the first element is the updated Nova proof and the second is the compressed decider proof.
    /// * `Err(WRAPSError::InvalidInput)` if input lengths are inconsistent.
    /// * `Err(WRAPSError::AddressBookSizeExceeded)` if any address book exceeds `MAX_AB_SIZE`.
    /// * `Err(WRAPSError::CryptographyError)` if any cryptographic primitive fails.
    pub fn construct_wraps_proof(
        pk: &ProvingKey,                                     // proving key output by sp1 setup
        vk: &VerificationKey,                                // verifying key output by sp1 setup
        ab_genesis_hash: &AddressBookHash,                   // genesis AddressBook hash
        prev_ab: &AddressBook,                               // current AddressBook
        next_ab: &AddressBook,                               // next AddressBook
        prev_proof: Option<UncompressedProofSerialized>,     // the previous proof
        hints_vk: impl AsRef<[u8]>,                          // TSS verification key for the next AddressBook
        aggregate_signature: &SchnorrSignature,              // threshold Schnorr signature attesting the next AddressBook
        bitvector: impl AsRef<[bool]>,                       // bitvector indicating which members signed the signature
    ) -> Result<(UncompressedProofSerialized, CompressedProofSerialized), WRAPSError> {
        if prev_ab.len() != bitvector.as_ref().len() {
            return Err(WRAPSError::InvalidInput(
                "AddressBook and bitvector lengths do not match".to_string()
            ));
        }

        if prev_ab.len() > MAX_AB_SIZE || next_ab.len() > MAX_AB_SIZE {
            return Err(WRAPSError::AddressBookSizeExceeded);
        }

        // pad up inputs to MAX_AB_SIZE
        // Ensure both address books and the participation bitmap align with circuit expectations.
        let padded_prev_ab = pad_addressbook(prev_ab);
        let padded_next_ab = pad_addressbook(next_ab);
        let padded_bitvector: [bool; MAX_AB_SIZE] = {
            let mut vec = bitvector.as_ref().to_vec();
            vec.resize(MAX_AB_SIZE, false);
            vec.try_into().unwrap()
        };

        let is_genesis: bool = prev_proof.is_none();
        if is_genesis {
            // ensure genesis ab hash matches
            assert_eq!(*ab_genesis_hash, hash_addressbook(&padded_prev_ab)?);
            // first proof uses same address book for current and next
            assert_eq!(hash_addressbook(&padded_next_ab)?, hash_addressbook(&padded_prev_ab)?);
        }

        // Build the message the committee signed to authorize the rotation.
        let ab_rotation_message: Vec<u8> = Self::compute_rotation_message(&padded_next_ab, hints_vk.as_ref())?;

        // compute aggregate public key
        let aggregate_pubkey: ark_ec::twisted_edwards::Affine<ark_ed_on_bn254::EdwardsConfig> = (0..prev_ab.len())
            .filter(|&i| bitvector.as_ref()[i])
            .fold(ark_ed_on_bn254::EdwardsAffine::zero(),|acc, i| acc.add(&prev_ab[i].0.clone()).into_affine());

        let schnorr_parameters = Schnorr::setup([0u8; 32]).unwrap();
        assert!(Schnorr::verify(&schnorr_parameters, &aggregate_pubkey, &ab_rotation_message, &aggregate_signature).unwrap());

        let external_inputs_at_step = prepare_external_inputs(
            &aggregate_signature,
            &padded_prev_ab,
            &padded_next_ab,
            hints_vk.as_ref(),
            &padded_bitvector,
        )?;

        let mut ivc_instance = if is_genesis {
            let F_circuit = Circuit::new(()).map_err(|_| WRAPSError::CryptographyError)?;
            // Seed the Nova instance with the initial ledger state.
            let initial_state = vec![
                hash_addressbook(&padded_prev_ab)?,
                hash_hints_vk(hints_vk.as_ref())?
            ];
            let mut instance = N::init(&(pk.nova_pp.clone(), vk.nova_vp.clone()), F_circuit, initial_state.clone())
                .map_err(|_| WRAPSError::CryptographyError)?;
            // Execute the first step using the prepared external inputs.
            instance.prove_step(thread_rng(), VecF(external_inputs_at_step.clone()), None)
                .map_err(|_| WRAPSError::CryptographyError)?;
            instance
        } else {
            // Resume the incremental IVC from the previous proof.
            let ivc_proof = NovaProof::deserialize_compressed(prev_proof.unwrap().as_slice()).unwrap();
            N::from_ivc_proof(ivc_proof, (), (pk.nova_pp.clone(), vk.nova_vp.clone()))
                .map_err(|_| WRAPSError::CryptographyError)?
        };

        // Fold in the current rotation step and immediately sanity-check the resulting IVC proof.
        ivc_instance.prove_step(thread_rng(), VecF(external_inputs_at_step.clone()), None)
            .map_err(|_| WRAPSError::CryptographyError)?;
        N::verify(vk.nova_vp.clone(), ivc_instance.ivc_proof())
            .map_err(|_| WRAPSError::CryptographyError)?;

        let mut next_ivc_proof_encoded = vec![];
        // Persist the updated uncompressed IVC proof for future iterations.
        ivc_instance.ivc_proof().serialize_compressed(&mut next_ivc_proof_encoded).unwrap();

        // Produce the succinct decider proof for the current state transition.
        let proof = D::prove(thread_rng(), &pk.decider_pp, ivc_instance.clone())
            .map_err(|_| WRAPSError::CryptographyError)?;

        // Double-check the decider proof before returning to catch internal inconsistencies.
        let verified = D::verify(
            vk.decider_vp.clone(),
            ivc_instance.i,
            ivc_instance.z_0.clone(),
            ivc_instance.z_i.clone(),
            &ivc_instance.U_i.get_commitments(),
            &ivc_instance.u_i.get_commitments(),
            &proof,
        ).map_err(|_| WRAPSError::CryptographyError)?;
        assert!(verified);

        // serialize the proof
        let compressed_proof = ProofData {
            i: ivc_instance.i,
            z_0: ivc_instance.z_0,
            z_i: ivc_instance.z_i,
            U_i_commitments: ivc_instance.U_i.get_commitments(),
            u_i_commitments: ivc_instance.u_i.get_commitments(),
            proof,
        };
        let mut compressed_proof_serialized = vec![];
        // Archive the decider proof in compressed form for on-chain / off-chain verification.
        compressed_proof.serialize_compressed(&mut compressed_proof_serialized).unwrap();

        // NOTE: constructing the proof uses the default proving binary artifacts (decider_pp and friends),
        // and therefore the proof verification must use the verification key associated with these same artifacts.
        // So we don't want to use the verification key that is currently used in the library for stand-alone
        // verification calls, and instead we must use the correct key. See `WRAPSVerificationKey` in Java for details.
        let decider_vp_serialized = Self::get_compressed_verification_key_bytes(vk)?;

        assert!(Self::verify_compressed_wraps_proof(
            &decider_vp_serialized,
            &compressed_proof_serialized,
            ab_genesis_hash,
            hints_vk.as_ref(),
        ).map_err(|_| WRAPSError::CryptographyError)?);

        Ok((next_ivc_proof_encoded, compressed_proof_serialized))
    }

    /// Checks a compressed WRAPS proof against a compressed verification key.
    ///
    /// # Arguments
    /// * `compressed_vk_serialized` - Compressed decider verifier parameters produced by [`get_compressed_verification_key_bytes`].
    /// * `proof_serialized` - Compressed proof bundle returned by [`construct_wraps_proof`].
    ///
    /// # Returns
    /// * `Ok(true)` if the decider successfully verifies the proof.
    /// * `Ok(false)` if verification fails.
    /// * `Err(folding_schemes::Error)` if deserialization or verification encounters an error.
    pub fn verify_compressed_wraps_proof(
        compressed_vk_serialized: &CompressedVerificationKeySerialized,
        proof_serialized: &CompressedProofSerialized,
        ab_genesis_hash: &AddressBookHash,
        hints_vk: impl AsRef<[u8]>
    ) -> Result<bool, WRAPSError> {
        type N = Nova<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
        type D = DeciderEth<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, Groth16<PairingCurve>, N>;

        // Decode the decider verification parameters from serialized form.
        let decider_vp =
            VerifierParam::<
                G1,
                <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::VerifierParams,
                <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::VerifyingKey,
            >::deserialize_compressed(compressed_vk_serialized.as_slice())
            .map_err(|_| WRAPSError::CryptographyError)?;

        // Decode the proof bundle emitted during `construct_wraps_proof`.
        let compressed_proof = ProofData::deserialize_compressed(proof_serialized.as_slice())
            .map_err(|_| WRAPSError::CryptographyError)?;

        // Does the i-th state of IVC have the expected hints_vk?
        let hints_vk_verified = compressed_proof.z_i[1] == hash_hints_vk(hints_vk.as_ref())?;
        // Does the initial state of IVC have the expected genesis ledger ID?
        let ledger_id_verified = compressed_proof.z_0[0] == *ab_genesis_hash;

        // Delegate verification to the decider gadget and return its verdict.
        let proof_verified = D::verify(
            decider_vp,
            compressed_proof.i,
            compressed_proof.z_0,
            compressed_proof.z_i,
            &compressed_proof.U_i_commitments,
            &compressed_proof.u_i_commitments,
            &compressed_proof.proof,
        ).map_err(|_| WRAPSError::CryptographyError)?;

        Ok(proof_verified && hints_vk_verified && ledger_id_verified)
    }
}

#[cfg(test)]
mod tests {
    use crate::preprocessing::WRAPSPreprocessing;

    use super::*;
    use std::{env, path::PathBuf};

    fn create_new_addressbook() -> (AddressBook, Keys) {
        let rng = &mut thread_rng();
        let schnorr_parameters = Schnorr::setup(rng.gen()).unwrap();
        let mut keys = Vec::new();
        let mut ab = Vec::new();
        let ab_size = rng.gen_range(MAX_AB_SIZE/4..=MAX_AB_SIZE);
        for _i in 0..ab_size {
            let (pk, sk) = Schnorr::keygen(&schnorr_parameters, rng.gen()).unwrap();
            let weight = Fr::from(1);
            keys.push(sk);
            ab.push((pk, weight));
        }
        (ab.try_into().unwrap(), keys.try_into().unwrap())
    }

    fn even_bitvector(ab: &AddressBook) -> Vec<bool> {
        ab.iter().enumerate().map(|(i, _)| i % 2 == 0 || i % 3 == 0).collect()
    }

    fn signing_subset<'a>(
        ab: &'a AddressBook,
        keys: &'a Keys,
        bitvector: impl AsRef<[bool]>,
    ) -> (Vec<SchnorrPubKey>, Vec<&'a SchnorrPrivKey>) {
        let mut pks = Vec::new();
        let mut sk_refs = Vec::new();
        for i in 0..bitvector.as_ref().len() {
            if bitvector.as_ref()[i] {
                pks.push(ab[i].0);
                sk_refs.push(&keys[i]);
            }
        }
        (pks, sk_refs)
    }

    fn threshold_sign(message_to_sign: &[u8], pks: &[SchnorrPubKey], sk_refs: &[&SchnorrPrivKey]) -> SchnorrSignature {
        let n = pks.len();
        let rng = &mut thread_rng();
        let seeds: Vec<[u8; ENTROPY_SIZE]> = (0..pks.len())
            .map(|_| rng.gen())
            .collect();

        // Round 1 for each participant
        let r1_msgs: Vec<SigningProtocolMessage> = (0..n)
            .map(|i| match WRAPS::signing_protocol(
                SigningProtocolPhase::R1,
                Some(seeds[i]),
                message_to_sign,
                None,
                &[],
                &[],
                &[],
                &[]
            ).unwrap() {
                SigningProtocolObject::ProtocolMessage(m) => m,
                _ => unreachable!(),
            })
            .collect();

        // Round 2 for each participant
        let r2_msgs: Vec<SigningProtocolMessage> = (0..n)
            .map(|i| match WRAPS::signing_protocol(
                SigningProtocolPhase::R2,
                Some(seeds[i]),
                message_to_sign,
                None,
                pks,
                &r1_msgs,
                &[],
                &[]
            ).unwrap() {
                SigningProtocolObject::ProtocolMessage(m) => m,
                _ => unreachable!(),
            })
            .collect();

        // Round 3 for each participant (signers only)
        let r3_msgs: Vec<SigningProtocolMessage> = (0..n)
            .map(|i| match WRAPS::signing_protocol(
                SigningProtocolPhase::R3,
                Some(seeds[i]),
                message_to_sign,
                Some(sk_refs[i]),
                pks,
                &r1_msgs,
                &r2_msgs,
                &[]
            ).unwrap() {
                SigningProtocolObject::ProtocolMessage(m) => m,
                _ => unreachable!(),
            })
            .collect();

        // Aggregate signatures
        match WRAPS::signing_protocol(
            SigningProtocolPhase::Aggregate,
            None, // no entropy for aggregation
            message_to_sign,
            None,
            pks,
            &r1_msgs,
            &r2_msgs,
            &r3_msgs,
        ).unwrap() {
            SigningProtocolObject::ProtocolOutput(sig) => sig,
            _ => unreachable!(),
        }
    }

    #[test]
    fn wraps_simulation() {
        let num_steps = 10;
        let load_params_from_disk = false;

        let (wraps_pk, wraps_vk) = if load_params_from_disk {
            let start = std::time::Instant::now();
            let cwd = env::current_dir().unwrap();
            let nova_pp_bytes = std::fs::read(cwd.join("resources/nova_pp.bin")).unwrap();
            let nova_vp_bytes = std::fs::read(cwd.join("resources/nova_vp.bin")).unwrap();
            let decider_pp_bytes = std::fs::read(cwd.join("resources/decider_pp.bin")).unwrap();
            let decider_vp_bytes = std::fs::read(cwd.join("resources/decider_vp.bin")).unwrap();
            println!("Read all parameters from disk: {:?}", start.elapsed());

            let start = std::time::Instant::now();
            let wraps_pk = WRAPS::setup_prover(nova_pp_bytes, decider_pp_bytes).unwrap();
            let wraps_vk = WRAPS::setup_verifier(nova_vp_bytes, decider_vp_bytes).unwrap();
            println!("Parsed all parameters: {:?}", start.elapsed());
            (wraps_pk, wraps_vk)
        } else {
            let start = std::time::Instant::now();
            let (wraps_pk, wraps_vk) = WRAPSPreprocessing::trusted_wraps_setup().unwrap();
            println!("Generated all parameters: {:?}", start.elapsed());
            (wraps_pk, wraps_vk)
        };

        let schnorr_parameters = Schnorr::setup([0u8; 32]).unwrap();
        // Build genesis address book and keys
        let (genesis_ab, genesis_keys) = create_new_addressbook();
        let ab_genesis_hash = WRAPS::compute_addressbook_hash(&genesis_ab).unwrap();

        // -------------------------------- Global State across loop iterations --------------------------------
        let mut prev_uncompressed_wraps_proof = vec![];

        // --------------------------------------- Step 0 is special ---------------------------------------

        let (mut prev_ab, mut prev_keys) = (genesis_ab, genesis_keys);
        // compute a step of the IVC
        for i in 0..num_steps {
            let (next_ab, next_keys) = if i == 0 {
                (prev_ab.clone(), prev_keys.clone())
            } else {
                create_new_addressbook()
            };
            let next_tss_vk = [i as u8; 1480]; // placeholder for TSS vk bytes

            // message being signed via threshold Schnorr
            let message: Vec<u8> = WRAPS::compute_rotation_message(&next_ab, &next_tss_vk).unwrap();

            let (pks_present, sks_present) = signing_subset(&prev_ab, &prev_keys, &even_bitvector(&prev_ab));

            // compute aggregate public key
            let aggregate_pubkey = pks_present
                .iter()
                .fold(SchnorrPubKey::zero(), |acc, pk| (acc + pk).into_affine());

            // simulate the signing protocol
            let aggregate_signature = threshold_sign(&message, &pks_present, &sks_present);

            assert!(Schnorr::verify(&schnorr_parameters, &aggregate_pubkey, &message, &aggregate_signature).unwrap());

            let start = std::time::Instant::now();
            let (next_uncompressed, next_compressed) = WRAPS::construct_wraps_proof(
                &wraps_pk,
                &wraps_vk,
                &ab_genesis_hash,
                &prev_ab,
                &next_ab,
                if i == 0 { None } else { Some(prev_uncompressed_wraps_proof.clone()) },
                &next_tss_vk,
                &aggregate_signature,
                &even_bitvector(&prev_ab),
            ).expect("WRAPS proof should be created");
            println!("Step {} WRAPS proof creation time: {:?}", i, start.elapsed());

            let compressed_vk_bytes = WRAPS::get_compressed_verification_key_bytes(&wraps_vk).unwrap();
            let verified = WRAPS::verify_compressed_wraps_proof(
                &compressed_vk_bytes,
                &next_compressed,
                &ab_genesis_hash,
                &next_tss_vk
            ).unwrap();
            assert!(verified);

            prev_ab = next_ab;
            prev_keys = next_keys;
            prev_uncompressed_wraps_proof = next_uncompressed;
        }
    }
}
