//
// Copyright (C) 2025 Hedera Hashgraph, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::env;
use jni::objects::{JByteArray, JLongArray, JObject, JObjectArray, JValue};
use jni::sys::{jbyteArray, jboolean, jobject, jsize, jint, JNI_VERSION_1_2};
use jni::{JNIEnv, JavaVM};
use rayon;
use smallvec::SmallVec;
use sp1_sdk::{SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey};
use ab_rotation_lib::address_book::{AddressBook, Signatures};
use ab_rotation_lib::ed25519::{Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use ab_rotation_lib::sha256::HASH_LENGTH;
use crate::jni_util;
use crate::raps::RAPS;

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
    let _ = rayon::ThreadPoolBuilder::new().num_threads(num_of_cores).build_global();

    JNI_VERSION_1_2
}

/// JNI for HistoryLibraryBridge.snarkVerificationKey
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_snarkVerificationKey(
    mut env: JNIEnv,
    _instance: JObject,
    elf_jarray: JByteArray,
) -> jbyteArray {
    let elf_vec = match env.convert_byte_array(&elf_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let (pk, vk) = RAPS::proof_setup(&elf_vec);

    let mut pk_buf: Vec<u8> = Vec::new();
    match bincode::serialize_into(&mut pk_buf, &pk) {
        Ok(()) => (),
        Err(_) => return std::ptr::null_mut()
    };

    let mut vk_buf: Vec<u8> = Vec::new();
    match bincode::serialize_into(&mut vk_buf, &vk) {
        Ok(()) => (),
        Err(_) => return std::ptr::null_mut()
    };

    let serialized_pk = jni_util::u8_vec_to_jbyte_array(&env, &pk_buf);
    let serialized_vk = jni_util::u8_vec_to_jbyte_array(&env, &vk_buf);

    let keys_clz = match env.find_class("com/hedera/cryptography/rpm/ProvingAndVerifyingSnarkKeys") {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let keys_obj = match env.new_object(keys_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(serialized_pk)), JValue::from(&JObject::from_raw(serialized_vk))]) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    keys_obj.into_raw()
}

/// JNI for HistoryLibraryBridge.newSchnorrKeyPair
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_newSchnorrKeyPair(
    mut env: JNIEnv,
    _instance: JObject,
    random_jarray: JByteArray,
) -> jobject {
    let random_arr = match jni_util::build_entropy_array(&env, &random_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let (sk, vk) = RAPS::keygen(random_arr);

    let serialized_sk = jni_util::u8_vec_to_jbyte_array(&env, &sk.to_bytes().to_vec());
    let serialized_vk = jni_util::u8_vec_to_jbyte_array(&env, &vk.to_bytes().to_vec());

    let keys_clz = match env.find_class("com/hedera/cryptography/rpm/SigningAndVerifyingSchnorrKeys") {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let keys_obj = match env.new_object(keys_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(serialized_sk)), JValue::from(&JObject::from_raw(serialized_vk))]) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    keys_obj.into_raw()
}

/// JNI for HistoryLibraryBridge.signSchnorr
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_signSchnorr(
    env: JNIEnv,
    _instance: JObject,
    message_jarray: JByteArray,
    signing_key_jarray: JByteArray,
) -> jbyteArray {
    let message = match env.convert_byte_array(&message_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let signing_key_vec: Vec<u8> = match env.convert_byte_array(&signing_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let signing_key_arr: &[u8; SECRET_KEY_LENGTH] = match signing_key_vec.as_slice().try_into() {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let sk = SigningKey::from_bytes(signing_key_arr);

    let result = sk.sign(&message.to_vec()).0.to_vec();

    jni_util::u8_vec_to_jbyte_array(&env, &result)
}

/// JNI for HistoryLibraryBridge.verifySchnorr
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_verifySchnorr(
    env: JNIEnv,
    _instance: JObject,
    signature_jarray: JByteArray,
    message_jarray: JByteArray,
    verifying_key_jarray: JByteArray,
) -> jboolean {
    let signature_vec: Vec<u8> = match env.convert_byte_array(&signature_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let signature_arr: &[u8; SIGNATURE_LENGTH] = match signature_vec.as_slice().try_into() {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let signature = Signature(serde_big_array::Array(*signature_arr));

    let message = match env.convert_byte_array(&message_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let verifying_key_vec: Vec<u8> = match env.convert_byte_array(&verifying_key_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let verifying_key_arr: &[u8; PUBLIC_KEY_LENGTH] = match verifying_key_vec.as_slice().try_into() {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let vk = match VerifyingKey::from_bytes(verifying_key_arr) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    jboolean::from(vk.verify(message, &signature))
}

/// JNI for HistoryLibraryBridge.hashAddressBook
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_hashAddressBookImpl(
    mut env: JNIEnv,
    _instance: JObject,
    verifying_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
) -> jbyteArray {
    let (verifying_keys_array, weights) = match jni_util::build_address_book_arrays(&mut env, verifying_keys_jarray, weights_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let ab = AddressBook::new(verifying_keys_array, weights);
    let hash_option = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab);

    let hash = match hash_option {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    jni_util::u8_vec_to_jbyte_array(&env, &hash.to_vec())
}

/// JNI for HistoryLibraryBridge.hashHintsVerificationKey
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_hashHintsVerificationKey(
    env: JNIEnv,
    _instance: JObject,
    verification_key_jarray: JByteArray,
) -> jbyteArray {
    let verification_key = match env.convert_byte_array(&verification_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let hash = ab_rotation_lib::sha256::digest_sha256(verification_key);

    jni_util::u8_vec_to_jbyte_array(&env, &hash.to_vec())
}

/// JNI for HistoryLibraryBridge.proveChainOfTrust
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_proveChainOfTrustImpl(
    mut env: JNIEnv,
    _instance: JObject,
    snark_proving_key_jarray: JByteArray,
    snark_verifying_key_jarray: JByteArray,
    genesis_address_book_hash_jarray: JByteArray,
    current_address_book_verifying_keys_jarray: JObjectArray,
    current_address_book_weights_jarray: JLongArray,
    next_address_book_verifying_keys_jarray: JObjectArray,
    next_address_book_weights_jarray: JLongArray,
    current_address_book_proof_jarray: JByteArray,
    next_address_book_hints_verification_key_hash_jarray: JByteArray,
    signatures_jarray: JObjectArray,
) -> jbyteArray {
    let snark_proving_key_vec = match env.convert_byte_array(&snark_proving_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let pk: SP1ProvingKey = match bincode::deserialize(&snark_proving_key_vec) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let snark_verifying_key_vec = match env.convert_byte_array(&snark_verifying_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let vk: SP1VerifyingKey = match bincode::deserialize(&snark_verifying_key_vec) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let genesis_address_book_hash_vec = match env.convert_byte_array(&genesis_address_book_hash_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let genesis_address_book_hash_arr: [u8; HASH_LENGTH] = match genesis_address_book_hash_vec.as_slice().try_into() {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let (current_address_book_verifying_keys_array, current_address_book_weights) = match jni_util::build_address_book_arrays(&mut env, current_address_book_verifying_keys_jarray, current_address_book_weights_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let ab_curr = AddressBook::new(current_address_book_verifying_keys_array, current_address_book_weights);

    let (next_address_book_verifying_keys_array, next_address_book_weights) = match jni_util::build_address_book_arrays(&mut env, next_address_book_verifying_keys_jarray, next_address_book_weights_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let ab_next = AddressBook::new(next_address_book_verifying_keys_array, next_address_book_weights);

    let current_proof: Option<SP1ProofWithPublicValues> =
        if current_address_book_proof_jarray.is_null() {
            None
        } else {
            let proof_vec = match env.convert_byte_array(&current_address_book_proof_jarray) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };
            match bincode::deserialize(&proof_vec) {
                Ok(val) => Some(val),
                Err(_) => return std::ptr::null_mut()
            }
        };

    let next_address_book_hints_verification_key_hash_vec = match env.convert_byte_array(&next_address_book_hints_verification_key_hash_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let next_address_book_hints_verification_key_hash_arr: [u8; HASH_LENGTH] = match next_address_book_hints_verification_key_hash_vec.as_slice().try_into() {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let num_of_sigs = match env.get_array_length(&signatures_jarray) {
        Ok(len) => len,
        Err(_) => return std::ptr::null_mut()
    };
    let mut signatures_array:Vec<Option<Signature>> = Vec::with_capacity(num_of_sigs as usize);
    for i in 0..num_of_sigs as usize {
        let jobj = match env.get_object_array_element(&signatures_jarray, i as jsize) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        if jobj.is_null() {
            signatures_array.push(None);
        } else {
            let sig_vec = match env.convert_byte_array(&JByteArray::from(jobj)) {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };
            let sig_arr: [u8; SIGNATURE_LENGTH] = match sig_vec.as_slice().try_into() {
                Ok(val) => val,
                Err(_) => return std::ptr::null_mut()
            };
            let signature: Signature = Signature(serde_big_array::Array(sig_arr));

            signatures_array.push(Option::Some(signature));
        }
    }
    let signatures = Signatures(SmallVec::from_vec(signatures_array));

    let next_proof_option = RAPS::construct_rotation_proof(
        &pk,
        &vk,
        &genesis_address_book_hash_arr,
        &ab_curr,
        &ab_next,
        current_proof,
        &next_address_book_hints_verification_key_hash_arr,
        &signatures,
    );
    let next_proof = match next_proof_option {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let mut proof_buf: Vec<u8> = Vec::new();
    match bincode::serialize_into(&mut proof_buf, &next_proof) {
        Ok(_val) => (),
        Err(_) => return std::ptr::null_mut()
    };

    jni_util::u8_vec_to_jbyte_array(&env, &proof_buf)
}

/// JNI for HistoryLibraryBridge.verifyChainOfTrust
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_rpm_HistoryLibraryBridge_verifyChainOfTrust(
    env: JNIEnv,
    _instance: JObject,
    snark_verifying_key_jarray: JByteArray,
    proof_jarray: JByteArray,
) -> jboolean {
    let snark_verifying_key_vec = match env.convert_byte_array(&snark_verifying_key_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let vk: SP1VerifyingKey = match bincode::deserialize(&snark_verifying_key_vec) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let proof_vec = match env.convert_byte_array(&proof_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let proof: SP1ProofWithPublicValues = match bincode::deserialize(&proof_vec) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    jboolean::from(RAPS::verify_proof(&vk, &proof))
}
