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

use std::collections::HashMap;
use jni::JNIEnv;
use jni::objects::{JByteArray, JIntArray, JLongArray, JObject, JObjectArray, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobject, jsize};
use crate::hints::{AggregationKey, ExtendedPublicKey, HinTS, PartialSignature, SecretKey, ThresholdSignature, VerificationKey, Weight, CRS, F};
use crate::jni_util;

/// JNI for HintsLibraryBridge.generateSecretKey
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_generateSecretKey(
    env: JNIEnv,
    _instance: JObject,
    random_jarray: JByteArray,
) -> jbyteArray {
    let random_arr = match jni_util::build_entropy_array(&env, &random_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let secret_key = HinTS::keygen(random_arr);
    jni_util::serialize_object(&env, &secret_key)
}

/// JNI for HintsLibraryBridge.computeHints
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_computeHints(
    env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    secret_key_jarray: JByteArray,
    party_id: jint,
    n: jint,
) -> jbyteArray {
    let crs: CRS = match jni_util::deserialize_jbyte_array(&env, &crs_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let secret_key: SecretKey = match jni_util::deserialize_jbyte_array(&env, &secret_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let hint = HinTS::hint_gen(&crs, n as usize, party_id as usize, &secret_key);
    jni_util::serialize_object(&env, &hint)
}

/// JNI for HintsLibraryBridge.validateHintsKey
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_validateHintsKey(
    env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    hints_jarray: JByteArray,
    party_id: jint,
    n: jint,
) -> jboolean {
    let crs: CRS = match jni_util::deserialize_jbyte_array(&env, &crs_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let hints: ExtendedPublicKey = match jni_util::deserialize_jbyte_array(&env, &hints_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    jboolean::from(HinTS::verify_hint(&crs, n as usize, party_id as usize, &hints))
}

/// JNI for HintsLibraryBridge.preprocess
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_preprocess(
    mut env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    parties_jarray: JIntArray,
    hints_jarray: JObjectArray,
    weights_jarray: JLongArray,
    n: jint,
) -> jobject {
    let crs: CRS = match jni_util::deserialize_jbyte_array(&env, &crs_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    // ------------------------------------------------------------------------
    // build HashMap<usize, (Weight, ExtendedPublicKey)>
    let num_of_keys = match env.get_array_length(&parties_jarray) {
        Ok(len) => len,
        Err(_) => return std::ptr::null_mut()
    };
    let mut keys :Vec<jint> = vec![0; num_of_keys as usize];
    match env.get_int_array_region(parties_jarray, 0, keys.as_mut_slice()) {
        Ok(()) => {},
        Err(_) => return std::ptr::null_mut()
    };

    let mut weights :Vec<jlong> = vec![0; num_of_keys as usize];
    match env.get_long_array_region(weights_jarray, 0, weights.as_mut_slice()) {
        Ok(()) => {},
        Err(_) => return std::ptr::null_mut()
    };

    let mut hints_array:Vec<ExtendedPublicKey> = Vec::with_capacity(num_of_keys as usize);
    for i in 0..num_of_keys as usize {
        let jobj = match env.get_object_array_element(&hints_jarray, i as jsize) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let hints: ExtendedPublicKey = match jni_util::deserialize_jbyte_array(&env, &JByteArray::from(jobj)) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        hints_array.push(hints);
    }

    let mut signer_info: HashMap<usize, (Weight, ExtendedPublicKey)> = HashMap::with_capacity(num_of_keys as usize);
    for i in 0..num_of_keys as usize {
        signer_info.insert(keys[i] as usize, (Weight::from(weights[i] as i64), hints_array[i].clone()));
    }
    // finished building the map
    // ------------------------------------------------------------------------

    let (vk, ak) = HinTS::preprocess(n as usize, &crs, &signer_info);

    let serialized_vk = jni_util::serialize_object(&env, &vk);
    let serialized_ak = jni_util::serialize_object(&env, &ak);

    let keys_clz = match env.find_class("com/hedera/cryptography/hints/AggregationAndVerificationKeys") {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let keys_obj = match env.new_object(keys_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(serialized_vk)), JValue::from(&JObject::from_raw(serialized_ak))]) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    keys_obj.into_raw()
}

/// JNI for HintsLibraryBridge.signBls
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_signBls(
    env: JNIEnv,
    _instance: JObject,
    message_jarray: JByteArray,
    secret_key_jarray: JByteArray,
) -> jbyteArray {
    let message = match env.convert_byte_array(&message_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let secret_key: SecretKey = match jni_util::deserialize_jbyte_array(&env, &secret_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let signature = HinTS::sign(&message, &secret_key);
    jni_util::serialize_object(&env, &signature)
}

/// JNI for HintsLibraryBridge.verifyBls
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_verifyBls(
    env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    signature_jarray: JByteArray,
    message_jarray: JByteArray,
    extended_public_key_jarray: JByteArray,
) -> jboolean {
    let crs: CRS = match jni_util::deserialize_jbyte_array(&env, &crs_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let message = match env.convert_byte_array(&message_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let extended_public_key: ExtendedPublicKey = match jni_util::deserialize_jbyte_array(&env, &extended_public_key_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let signature: PartialSignature = match jni_util::deserialize_jbyte_array(&env, &signature_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    jboolean::from(HinTS::partial_verify(&crs, &message, &extended_public_key, &signature))
}

/// JNI for HintsLibraryBridge.aggregateSignatures
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_aggregateSignatures(
    mut env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    aggregation_key_jarray: JByteArray,
    verification_key_jarray: JByteArray,
    parties_jarray: JIntArray,
    partial_signatures_jarray: JObjectArray,
) -> jbyteArray {
    let crs: CRS = match jni_util::deserialize_jbyte_array(&env, &crs_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let aggregation_key: AggregationKey = match jni_util::deserialize_jbyte_array(&env, &aggregation_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let verification_key: VerificationKey = match jni_util::deserialize_jbyte_array(&env, &verification_key_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    // ------------------------------------------------------------------------
    // build HashMap<usize, PartialSignature>
    let num_of_keys = match env.get_array_length(&parties_jarray) {
        Ok(len) => len,
        Err(_) => return std::ptr::null_mut()
    };
    let mut keys :Vec<jint> = vec![0; num_of_keys as usize];
    match env.get_int_array_region(parties_jarray, 0, keys.as_mut_slice()) {
        Ok(()) => {},
        Err(_) => return std::ptr::null_mut()
    };

    let mut partial_signatures_array:Vec<PartialSignature> = Vec::with_capacity(num_of_keys as usize);
    for i in 0..num_of_keys as usize {
        let jobj = match env.get_object_array_element(&partial_signatures_jarray, i as jsize) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        let partial_signature: PartialSignature = match jni_util::deserialize_jbyte_array(&env, &JByteArray::from(jobj)) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };

        partial_signatures_array.push(partial_signature);
    }

    let mut partial_signatures: HashMap<usize, PartialSignature> = HashMap::with_capacity(num_of_keys as usize);
    for i in 0..num_of_keys as usize {
        partial_signatures.insert(keys[i] as usize, partial_signatures_array[i].clone());
    }
    // finished building the map
    // ------------------------------------------------------------------------

    let threshold_signature = HinTS::aggregate(&crs, &aggregation_key, &verification_key, &partial_signatures);
    jni_util::serialize_object(&env, &threshold_signature)
}

/// JNI for HintsLibraryBridge.verifyAggregate
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_verifyAggregate(
    env: JNIEnv,
    _instance: JObject,
    crs_jarray: JByteArray,
    signature_jarray: JByteArray,
    message_jarray: JByteArray,
    verification_key_jarray: JByteArray,
    threshold_numerator: jlong,
    threshold_denominator: jlong,
) -> jboolean {
    let crs: CRS = match jni_util::deserialize_jbyte_array(&env, &crs_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let signature: ThresholdSignature = match jni_util::deserialize_jbyte_array(&env, &signature_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let message = match env.convert_byte_array(&message_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let verification_key: VerificationKey = match jni_util::deserialize_jbyte_array(&env, &verification_key_jarray) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    jboolean::from(HinTS::verify(&crs, &message, &verification_key, &signature, (F::from(threshold_numerator), F::from(threshold_denominator))))
}
