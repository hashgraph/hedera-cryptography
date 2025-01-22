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

use ark_ff::PrimeField;
use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyte, jlong, jbyteArray, jsize, jboolean};
use jni::JNIEnv;
use crate::setup::{ContributionProof, PowersOfTauProtocol};
use crate::hints::{deserialize, serialize, CRS, F};

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

    let serialized_crs = serialize(&crs);
    let vec: Vec<jbyte> = serialized_crs.iter().map(|&x| x as jbyte).collect();

    let array = env.new_byte_array(vec.len() as i32);
    match env.set_byte_array_region(array.as_ref().unwrap(), 0, &vec) {
        Ok(()) => array.unwrap().into_raw(),
        Err(_) => {
            let _ = env.delete_local_ref(JObject::from(array.unwrap()));
            std::ptr::null_mut()
        }
    }
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
    let serialized_prev_crs = match env.convert_byte_array(&prev_crs_array) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let prev_crs :CRS = deserialize(&serialized_prev_crs);

    let random_vec = match env.convert_byte_array(&random_array) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let random = F::from_le_bytes_mod_order(&random_vec);

    let (crs, contribution_proof) = PowersOfTauProtocol::contribute(&prev_crs, random);

    let serialized_crs = serialize(&crs);
    let crs_vec: Vec<jbyte> = serialized_crs.iter().map(|&x| x as jbyte).collect();

    let serialized_contribution_proof = serialize(&contribution_proof);
    let contribution_proof_vec: Vec<jbyte> = serialized_contribution_proof.iter().map(|&x| x as jbyte).collect();

    let array = env.new_byte_array((crs_vec.len() + contribution_proof_vec.len()) as i32);
    match env.set_byte_array_region(array.as_ref().unwrap(), 0, &crs_vec) {
        Ok(()) => (),
        Err(_) => {
            let _ = env.delete_local_ref(JObject::from(array.unwrap()));
            return std::ptr::null_mut()
        }
    }

    match env.set_byte_array_region(array.as_ref().unwrap(), crs_vec.len() as jsize, &contribution_proof_vec) {
        Ok(()) => array.unwrap().into_raw(),
        Err(_) => {
            let _ = env.delete_local_ref(JObject::from(array.unwrap()));
            std::ptr::null_mut()
        }
    }
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
    let serialized_prev_crs = match env.convert_byte_array(&prev_crs_array) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let prev_crs :CRS = deserialize(&serialized_prev_crs);

    let serialized_next_crs = match env.convert_byte_array(&next_crs_array) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let next_crs :CRS = deserialize(&serialized_next_crs);

    let serialized_contribution_proof = match env.convert_byte_array(&contribution_proof_array) {
        Ok(val) => val,
        Err(_) => return jboolean::from(false)
    };
    let contribution_proof: ContributionProof = deserialize(&serialized_contribution_proof);

    jboolean::from(PowersOfTauProtocol::verify_contribution(&prev_crs, &next_crs, &contribution_proof))
}
