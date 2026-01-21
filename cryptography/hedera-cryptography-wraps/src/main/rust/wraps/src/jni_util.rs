// SPDX-License-Identifier: Apache-2.0

use jni::JNIEnv;
use jni::objects::{JBooleanArray, JByteArray, JObject, JObjectArray, JLongArray};
use jni::sys::{jboolean, jbyte, jbyteArray, jlong, jsize};
use ark_serialize::CanonicalDeserialize;

use crate::{ENTROPY_SIZE, AddressBook, AddressBookEntry, SchnorrAttestedPubKey, Weight, NodeId};

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

/// Builds an AddressBook out of a pair of public keys and weights arrays
pub fn build_address_book(
    env: &mut JNIEnv,
    schnorr_public_keys_jarray: JObjectArray,
    weights_jarray: JLongArray,
    node_ids_jarray: JLongArray,
) -> Result<AddressBook, ()> {
    let num_of_keys = match env.get_array_length(&schnorr_public_keys_jarray) {
        Ok(len) => len,
        Err(_) => return Result::Err(())
    };

    let mut weights_jlong: Vec<jlong> = vec![0; num_of_keys as usize];
    match env.get_long_array_region(weights_jarray, 0, weights_jlong.as_mut_slice()) {
        Ok(()) => {},
        Err(_) => return Result::Err(())
    };

    let mut node_ids_jlong: Vec<jlong> = vec![0; num_of_keys as usize];
    match env.get_long_array_region(node_ids_jarray, 0, node_ids_jlong.as_mut_slice()) {
        Ok(()) => {},
        Err(_) => return Result::Err(())
    };

    let mut entries: Vec<AddressBookEntry> = Vec::with_capacity(num_of_keys as usize);
    for i in 0..num_of_keys as usize {
        if weights_jlong[i] < 0 { return Result::Err(()); }

        let jobj = match env.get_object_array_element(&schnorr_public_keys_jarray, i as jsize) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };
        let key_vec = match env.convert_byte_array(&JByteArray::from(jobj)) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };
        let key = match SchnorrAttestedPubKey::deserialize_uncompressed(key_vec.as_slice()) {
            Ok(val) => val,
            Err(_) => return Result::Err(())
        };

        entries.push((key, Weight::from(weights_jlong[i] as u64), NodeId::from(node_ids_jlong[i] as u64)) as AddressBookEntry);
    }

    Result::Ok(entries as AddressBook)
}

/// Converts a JBooleanArray into a Vec<bool>
pub fn jboolean_array_to_vec(env: &JNIEnv, boolean_jarray: JBooleanArray) -> Result<Vec<bool>, ()> {
    let num = match env.get_array_length(&boolean_jarray) {
        Ok(len) => len as usize,
        Err(_) => return Result::Err(())
    };

    let mut jboolean_vec: Vec<jboolean> = vec![0; num];
    match env.get_boolean_array_region(boolean_jarray, 0, jboolean_vec.as_mut_slice()) {
        Ok(()) => {},
        Err(_) => return Result::Err(())
    };

    let mut vec: Vec<bool> = vec![];
    for i in 0..num {
        vec.push(jboolean_vec[i] != 0);
    }

    Result::Ok(vec)
}

