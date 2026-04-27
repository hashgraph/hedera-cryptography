// SPDX-License-Identifier: Apache-2.0

use jni::sys::{jbyteArray, jboolean, jobject, jsize, jint, JNI_VERSION_1_2};
use jni::{JNIEnv, JavaVM};
use jni::objects::{JByteArray, JObject, JObjectArray, JValue, JLongArray, JBooleanArray};
use std::env;
use ark_serialize::CanonicalDeserialize;
use ark_ff::{BigInteger, PrimeField};

use crate::{
    jni_util,
    utils,
    WRAPS,
    SigningProtocolPhase,
    ENTROPY_SIZE,
    SchnorrPrivKey,
    SchnorrAttestedPubKey,
    SigningProtocolMessage,
    SigningProtocolObject,
    SchnorrMultiSignature,
    AddressBook,
    AddressBookHash,
    UncompressedProofSerialized,
    CompressedProofSerialized,
    CompressedVerificationKeySerialized,
    hash_hints_vk
};

const SECRET_KEY_LENGTH: usize = 32;

/// The default level of parallelism if the TSS_LIB_NUM_OF_CORES env var is missing or invalid.
const DEFAULT_NUM_OF_CORES: usize = 1;

/// JNI_OnLoad gets called only once when the library is first loaded into the process
#[no_mangle]
pub extern "system" fn JNI_OnLoad(
    _vm: JavaVM,
    _reserved: *const u8,
) -> jint {
    // Limit the concurrency per the configuration. This can only be done once, and must be done
    // before the SNARK library has had a chance to do this. If we try to call `build_global()` again,
    // whether with the same num_of_cores or a different one, it will return an Err Result
    // and not have any effect.
    // So we do this here in this JNI_OnLoad function first thing when this library loads.
    let num_of_cores = match env::var("TSS_LIB_NUM_OF_CORES") {
        Ok(val) => val.parse::<usize>().unwrap_or(DEFAULT_NUM_OF_CORES),
        Err(_) => DEFAULT_NUM_OF_CORES
    };

    // NOTE: as of 10/14/2025, we actually don't use parallelism in WRAPS 2.0, and so we don't
    // really use rayon just yet. So today the below operation is effectively a no-op as this
    // doesn't affect anything in the WRAPS today.
    // However, we'll be adding support for parallelism in the near future to enable faster
    // computations. So we take a dependency on rayon and do this preemptively:
    let _ = rayon::ThreadPoolBuilder::new().num_threads(num_of_cores).build_global();

    JNI_VERSION_1_2
}

/// JNI for WRAPSLibraryBridge.generateSchnorrKeysImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_generateSchnorrKeysImpl(
    mut env: JNIEnv,
    _instance: JObject,
    random_jarray: JByteArray,
) -> jobject {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let random_arr = match jni_util::build_entropy_array(&env, &random_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let (private_key, public_key) = match WRAPS::keygen(random_arr) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let serialized_private_key = jni_util::u8_vec_to_jbyte_array(&env, &utils::serialize(&private_key));
        let serialized_public_key = jni_util::u8_vec_to_jbyte_array(&env, &utils::serialize(&public_key));

        let keys_clz = match env.find_class("com/hedera/cryptography/wraps/SchnorrKeys") {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let keys_obj = match env.new_object(keys_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(serialized_private_key)), JValue::from(&JObject::from_raw(serialized_public_key))]) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        keys_obj.into_raw()
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.runSigningProtocolPhaseImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_runSigningProtocolPhaseImpl(
    mut env: JNIEnv,
    _instance: JObject,
    phase_ordinal: jint,
    random_jarray: JByteArray,
    message_jarray: JByteArray,
    schnorr_private_key_jarray: JByteArray,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
    signers_jarray: JBooleanArray,
    round1messages_jarray: JObjectArray,
    round2messages_jarray: JObjectArray,
    round3messages_jarray: JObjectArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let phase = match phase_ordinal {
            0 => SigningProtocolPhase::R1,
            1 => SigningProtocolPhase::R2,
            2 => SigningProtocolPhase::R3,
            3 => SigningProtocolPhase::Aggregate,
            _ => return std::ptr::null_mut()
        };

        let random_arr: Option<[u8; ENTROPY_SIZE]> = if random_jarray.is_null() { None } else {
            match jni_util::build_entropy_array(&env, &random_jarray) {
                Ok(val) => Some(val),
                Err(_) => return std::ptr::null_mut()
            }
        };

        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let signing_key: Option<SchnorrPrivKey> = if schnorr_private_key_jarray.is_null() { None } else {
            let signing_key_vec: Vec<u8> = match env.convert_byte_array(&schnorr_private_key_jarray) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };
            let signing_key_arr: &[u8; SECRET_KEY_LENGTH] = match signing_key_vec.as_slice().try_into() {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };
            match SchnorrPrivKey::deserialize_uncompressed(&signing_key_arr[..]) {
                Ok(val) => Some(val),
                Err(_) => return std::ptr::null_mut()
            }
        };

        let ab: AddressBook = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let signers: Vec<bool> = match jni_util::jboolean_array_to_vec(&env, signers_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let round1messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round1messages_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let round2messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round2messages_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let round3messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round3messages_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let obj: SigningProtocolObject = match WRAPS::signing_protocol(phase, random_arr, message, signing_key.as_ref(), &ab, &signers, &round1messages, &round2messages, &round3messages) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let serialized_obj = match obj {
            SigningProtocolObject::ProtocolMessage(msg_encoded) => utils::serialize(&msg_encoded),
            SigningProtocolObject::ProtocolOutput(signature) => utils::serialize(&signature)
        };

        jni_util::u8_vec_to_jbyte_array(&env, &serialized_obj)
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.verifySignatureImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_verifySignatureImpl(
    mut env: JNIEnv,
    _instance: JObject,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
    message_jarray: JByteArray,
    signature_jarray: JByteArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab: AddressBook = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let message = match env.convert_byte_array(&message_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let signature: SchnorrMultiSignature = {
            let signature_vec: Vec<u8> = match env.convert_byte_array(&signature_jarray) {
                Ok(val) => val,
                Err(_) => return jboolean::from(false)
            };
            match SchnorrMultiSignature::deserialize_uncompressed(signature_vec.as_slice()) {
                Ok(val) => val,
                Err(_) => return jboolean::from(false)
            }
        };

        match WRAPS::verify_signature(&ab, message, &signature) {
            Ok(val) => jboolean::from(val),
            Err(_) => return jboolean::from(false)
        }
    })).unwrap_or_else(|_| jboolean::from(false))
}

/// JNI for WRAPSLibraryBridge.hashAddressBookImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_hashAddressBookImpl(
    mut env: JNIEnv,
    _instance: JObject,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab: AddressBook = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let hash: AddressBookHash = match WRAPS::compute_addressbook_hash(&ab) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let serialized_hash = utils::serialize(&hash);

        jni_util::u8_vec_to_jbyte_array(&env, &serialized_hash)
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.hashArrayImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_hashArrayImpl(
    env: JNIEnv,
    _instance: JObject,
    input_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if input_jarray.is_null() {
            return std::ptr::null_mut()
        }
        let input_vec: Vec<u8> = match env.convert_byte_array(&input_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        if input_vec.is_empty() {
            return std::ptr::null_mut()
        }

        // NOTE: hash_hints_vk() works for any vector. It's not specific to hints verification keys at all.
        let hash: Vec<u8> = match hash_hints_vk(&input_vec) {
            Ok(val) => val.into_bigint().to_bytes_le(),
            Err(_) => return std::ptr::null_mut()
        };

        jni_util::u8_vec_to_jbyte_array(&env, &hash)
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.formatRotationMessageImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_formatRotationMessageImpl(
    mut env: JNIEnv,
    _instance: JObject,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
    tss_vk_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab: AddressBook = match jni_util::build_address_book(&mut env, schnorr_public_keys_jarray, weights_jarray, node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let tss_vk_vec: Vec<u8> = match env.convert_byte_array(&tss_vk_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let msg = match WRAPS::compute_rotation_message(&ab, &tss_vk_vec) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        jni_util::u8_vec_to_jbyte_array(&env, &msg)
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.constructWrapsProofImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_constructWrapsProofImpl(
    mut env: JNIEnv,
    _instance: JObject,
    ab_genesis_hash_jarray: JByteArray,
    prev_schnorr_public_keys_jarray: JObjectArray,
    prev_weights_jarray: JLongArray,
    prev_node_ids_jarray: JLongArray,
    next_schnorr_public_keys_jarray: JObjectArray,
    next_weights_jarray: JLongArray,
    next_node_ids_jarray: JLongArray,
    prev_proof_jarray: JByteArray,
    tss_vk_jarray: JByteArray,
    signature_jarray: JByteArray,
) -> jbyteArray {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab_genesis_hash: AddressBookHash = {
            let ab_genesis_hash_vec: Vec<u8> = match env.convert_byte_array(&ab_genesis_hash_jarray) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };
            match AddressBookHash::deserialize_uncompressed(ab_genesis_hash_vec.as_slice()) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            }
        };

        let prev_ab: AddressBook = match jni_util::build_address_book(&mut env, prev_schnorr_public_keys_jarray, prev_weights_jarray, prev_node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let next_ab: AddressBook = match jni_util::build_address_book(&mut env, next_schnorr_public_keys_jarray, next_weights_jarray, next_node_ids_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let prev_proof: Option<UncompressedProofSerialized> = if prev_proof_jarray.is_null() { None } else {
            match env.convert_byte_array(&prev_proof_jarray) {
                Ok(val) => Some(val as UncompressedProofSerialized),
                Err(_) => return std::ptr::null_mut()
            }
        };

        let tss_vk_vec: Vec<u8> = match env.convert_byte_array(&tss_vk_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let signature: SchnorrMultiSignature = {
            let signature_vec: Vec<u8> = match env.convert_byte_array(&signature_jarray) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };
            match SchnorrMultiSignature::deserialize_uncompressed(signature_vec.as_slice()) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            }
        };

        let pk = match utils::get_proving_key() {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let vk = match utils::get_verification_key() {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let (uncompressed_proof, compressed_proof): (UncompressedProofSerialized, CompressedProofSerialized) = match WRAPS::construct_wraps_proof(
                pk.get_ref(),
                &vk,
                &ab_genesis_hash,
                &prev_ab,
                &next_ab,
                prev_proof,
                tss_vk_vec,
                &signature) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let uncompressed_proof_jarray = jni_util::u8_vec_to_jbyte_array(&env, &uncompressed_proof);
        let compressed_proof_jarray = jni_util::u8_vec_to_jbyte_array(&env, &compressed_proof);

        let proof_clz = match env.find_class("com/hedera/cryptography/wraps/Proof") {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let proof_obj = match env.new_object(proof_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(uncompressed_proof_jarray)), JValue::from(&JObject::from_raw(compressed_proof_jarray))]) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        proof_obj.into_raw()
    })).unwrap_or_else(|_| std::ptr::null_mut())
}

/// JNI for WRAPSLibraryBridge.verifyCompressedProofImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_verifyCompressedProofImpl(
    env: JNIEnv,
    _instance: JObject,
    compressed_proof_jarray: JByteArray,
    ab_genesis_hash_jarray: JByteArray,
    tss_vk_jarray: JByteArray,
    wraps_vk_jarray: JByteArray,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ab_genesis_hash: AddressBookHash = {
            let ab_genesis_hash_vec: Vec<u8> = match env.convert_byte_array(&ab_genesis_hash_jarray) {
                Ok(val) => val,
                Err(_) => return jboolean::from(false)
            };
            match AddressBookHash::deserialize_uncompressed(ab_genesis_hash_vec.as_slice()) {
                Ok(val) => val,
                Err(_) => return jboolean::from(false)
            }
        };

        let tss_vk_vec: Vec<u8> = match env.convert_byte_array(&tss_vk_jarray) {
            Ok(val) => val,
            Err(_) => return jboolean::from(false)
        };

        let compressed_proof = match env.convert_byte_array(&compressed_proof_jarray) {
            Ok(val) => val as CompressedProofSerialized,
            Err(_) => return jboolean::from(false)
        };

        let decider_vp_serialized = match env.convert_byte_array(&wraps_vk_jarray) {
            Ok(val) => val as CompressedVerificationKeySerialized,
            Err(_) => return jboolean::from(false)
        };

        match WRAPS::verify_compressed_wraps_proof(&decider_vp_serialized, &compressed_proof, &ab_genesis_hash, tss_vk_vec) {
            Ok(val) => jboolean::from(val),
            Err(_) => return jboolean::from(false)
        }
    })).unwrap_or_else(|_| jboolean::from(false))
}
