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

use jni::objects::{JByteArray, JObject};
use jni::sys::{jlong, jbyteArray, jboolean};
use jni::JNIEnv;
use crate::setup::{ContributionProof, PowersOfTauProtocol};
use crate::hints::{serialize, CRS};
use crate::jni_util;

/// JNI function to create a new CRS object
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `signers_num` the number of signers
/// # Returns
/// *   a byte array with a serialized CRS object, or null on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_initCRS(
    env: JNIEnv,
    _instance: JObject,
    signers_num: jlong,
) -> jbyteArray {
    let crs = PowersOfTauProtocol::init(signers_num as usize);
    jni_util::serialize_object(&env, &crs)
}

/// JNI function to update a CRS object
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `prev_crs_array` the previous CRS
/// * `random_array` the randomness
/// # Returns
/// *   a byte array with a serialized next CRS object and its contribution proof, or null on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_updateCRS(
    env: JNIEnv,
    _instance: JObject,
    prev_crs_array: JByteArray,
    random_array: JByteArray,
) -> jbyteArray {
    let prev_crs :CRS = match jni_util::deserialize_jbyte_array(&env, &prev_crs_array) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let random_arr = match jni_util::build_entropy_array(&env, &random_array) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let (crs, contribution_proof) = PowersOfTauProtocol::contribute(&prev_crs, random_arr);

    let serialized_crs = serialize(&crs);
    let serialized_contribution_proof = serialize(&contribution_proof);

    jni_util::two_u8_vec_to_jbyte_array(&env, &serialized_crs, &serialized_contribution_proof)
}

/// JNI function to verify the next CRS object with its ContributionProof
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `prev_crs_array` the previous CRS
/// * `next_crs_array` the next CRS
/// * `contribution_proof_array` the contribution proof
/// # Returns
/// *   true if verified, false if unverified or on error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_hints_HintsLibraryBridge_verifyCRS(
    env: JNIEnv,
    _instance: JObject,
    prev_crs_array: JByteArray,
    next_crs_array: JByteArray,
    contribution_proof_array: JByteArray,
) -> jboolean {
    let prev_crs :CRS = match jni_util::deserialize_jbyte_array(&env, &prev_crs_array) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let next_crs :CRS = match jni_util::deserialize_jbyte_array(&env, &next_crs_array) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    let contribution_proof: ContributionProof = match jni_util::deserialize_jbyte_array(&env, &contribution_proof_array) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };

    jboolean::from(PowersOfTauProtocol::verify_contribution(&prev_crs, &next_crs, &contribution_proof))
}
