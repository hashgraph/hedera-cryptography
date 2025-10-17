// SPDX-License-Identifier: Apache-2.0

use jni::JNIEnv;
use jni::objects::{JByteArray, JObject, JObjectArray};
use jni::sys::{jbyte, jbyteArray, jlong, jsize};
use ark_serialize::CanonicalDeserialize;

use crate::ENTROPY_SIZE;

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

/// Creates a `[u8; ENTROPY_SIZE]` array out of a given Java byte array,
/// which must be of size ENTROPY_SIZE.
/// # Arguments
/// * `env` - The JNI environment.
/// * `random_array` the Java byte array of size ENTROPY_SIZE
/// # Returns
/// *   an entropy array as accepted by WRAPS functions, or Err
pub fn build_entropy_array(env: &JNIEnv, random_array: &JByteArray) -> Result<[u8; ENTROPY_SIZE], ()> {
    let random_vec = match env.convert_byte_array(&random_array) {
        Ok(val) => val,
        Err(_) => return Result::Err(())
    };
    let random_arr :[u8; ENTROPY_SIZE] = match random_vec.try_into() {
        Ok(val) => val,
        Err(_) => return Result::Err(())
    };
    Ok(random_arr)
}

/// Creates a Vec<T: CanonicalDeserialize> out of a Java byte[][] by deserializing objects. Nulls produce errors.
pub fn build_vector<T: CanonicalDeserialize>(env: &mut JNIEnv, java_array: &JObjectArray) -> Result<Vec<T>, ()> {
    let len = match env.get_array_length(java_array) {
        Ok(len) => len,
        Err(_) => return Result::Err(())
    };

    let mut vec:Vec<T> = Vec::with_capacity(len as usize);
    for i in 0..len as usize {
        let jobj = match env.get_object_array_element(java_array, i as jsize) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };

        if jobj.is_null() {
            return Result::Err(());
        }

        let jobj_vec = match env.convert_byte_array(&JByteArray::from(jobj)) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };

        let obj = match T::deserialize_uncompressed(jobj_vec.as_slice()) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };

        vec.push(obj);
    }

    Ok(vec)
}