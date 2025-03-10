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

use ab_rotation_lib::ed25519::{VerifyingKey, ENTROPY_SIZE, PUBLIC_KEY_LENGTH};
use jni::JNIEnv;
use jni::objects::{JByteArray, JLongArray, JObject, JObjectArray};
use jni::sys::{jbyte, jbyteArray, jlong, jsize};

const RANDOM_SIZE: usize = ENTROPY_SIZE;

/// Creates a jbyteArray out of a Vec<jbyte> object.
/// # Arguments
/// * `env` - The JNI environment.
/// * `vec` the input vector
/// # Returns
/// *   a byte array with the input vector written, or null on error
pub fn jbyte_vec_to_jbyte_array(env: &JNIEnv, vec: &Vec<jbyte>) -> jbyteArray {
    let array = match env.new_byte_array(vec.len() as i32) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    match env.set_byte_array_region(&array, 0, &vec) {
        Ok(()) => array.into_raw(),
        Err(_) => {
            let _ = env.delete_local_ref(JObject::from(array));
            std::ptr::null_mut()
        }
    }
}

/// Creates a jbyteArray out of a Vec<u8> object.
/// # Arguments
/// * `env` - The JNI environment.
/// * `vec` the input vector
/// # Returns
/// *   a byte array with the input vector written, or null on error
pub fn u8_vec_to_jbyte_array(env: &JNIEnv, vec: &Vec<u8>) -> jbyteArray {
    let jbyte_vec = vec.iter().map(|&x| x as jbyte).collect();
    jbyte_vec_to_jbyte_array(env, &jbyte_vec)
}

/// Creates a `[u8; RANDOM_SIZE]` array out of a given Java byte array,
/// which must be of size RANDOM_SIZE (currently 32).
/// # Arguments
/// * `env` - The JNI environment.
/// * `random_array` the Java byte array of size RANDOM_SIZE
/// # Returns
/// *   an entropy array as accepted by the CRS/HinTS implementation, or Err
pub fn build_entropy_array(env: &JNIEnv, random_array: &JByteArray) -> Result<[u8; RANDOM_SIZE], ()> {
    let random_vec = match env.convert_byte_array(&random_array) {
        Ok(val) => val,
        Err(_) => return Result::Err(())
    };
    let random_arr :[u8; RANDOM_SIZE] = match random_vec.try_into() {
        Ok(val) => val,
        Err(_) => return Result::Err(())
    };
    Ok(random_arr)
}

/// Builds a pair of verifying keys and weights arrays as consumed by the RAPS library
/// to model the address book.
pub fn build_address_book_arrays(
    env: &mut JNIEnv,
    verifying_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
) -> Result<(Vec<VerifyingKey>, Vec<u64>), ()> {
    let num_of_keys = match env.get_array_length(&verifying_keys_jarray) {
        Ok(len) => len,
        Err(_) => return Result::Err(())
    };

    let mut verifying_keys_array:Vec<VerifyingKey> = Vec::with_capacity(num_of_keys as usize);
    for i in 0..num_of_keys as usize {
        let jobj = match env.get_object_array_element(&verifying_keys_jarray, i as jsize) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };

        let key_vec = match env.convert_byte_array(&JByteArray::from(jobj)) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };
        let key_arr: [u8; PUBLIC_KEY_LENGTH] = match key_vec.as_slice().try_into() {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };
        let key = match VerifyingKey::from_bytes(&key_arr) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };

        verifying_keys_array.push(key);
    }

    let mut weights_jlong :Vec<jlong> = vec![0; num_of_keys as usize];
    match env.get_long_array_region(weights_jarray, 0, weights_jlong.as_mut_slice()) {
        Ok(()) => {},
        Err(_) => return Result::Err(())
    };

    let weights :Vec<u64> = weights_jlong.iter().map(|x| *x as u64).collect();

    Result::Ok((verifying_keys_array, weights))
}

