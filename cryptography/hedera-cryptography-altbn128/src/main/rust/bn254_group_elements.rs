//
// Copyright (C) 2024 Hedera Hashgraph, LLC
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

use crate::group_element_utils::*;
use crate::jni_helpers;
use crate::jni_helpers::{to_point, BUSINESS_ERROR_POINT_NOT_IN_CURVE, G1, G2};
use jni::objects::{JByteArray, JLongArray, JObject, JObjectArray};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;
const GROUP1_ELEMENT_SIZE: usize = 64;
const GROUP2_ELEMENT_SIZE: usize = 128;
const GROUP1: i32 = 0;

type G1Config = ark_bn254::g1::Config;
type G2Config = ark_bn254::g2::Config;

/// JNI function to create a new random group element from a seed value
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `input_seed`   the byte array of size GROUP2_ELEMENT_SIZE represents the group element
/// * `group_id`  in which group to perform the operation
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsFromSeed(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    input_seed: JByteArray,
    output: JByteArray,
) -> jint {
    let seed_array = match jni_helpers::extract_random_seed(&env, &input_seed) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let mut rng = ChaCha8Rng::from_seed(seed_array);
    match group_id {
        GROUP1 => {
            type G = G1;
            let point = group_elements_from_random::<G, ChaCha8Rng>(&mut rng);
            jni_helpers::serialize_to_jbytearray::<G>(env, &point, output)
                .unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = group_elements_from_random::<G, ChaCha8Rng>(&mut rng);
            jni_helpers::serialize_to_jbytearray::<G>(env, &point, output)
                .unwrap_or_else(|value| value)
        }
    }
}

/// JNI function that attempts to obtain a group element from a 256-bit hash
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `input_x`   a 256-bit byte array that represents the x coordinate of the group element
/// * `group_id`  in which group to perform the operation
/// * `output`    the byte array that will be filled with the resulting group element, the size
///               depends on the group. it will be unchanged in case the point is not in the curve
/// # Returns
/// *   0    Success
/// *   -4   Business Error: Point is not in the curve
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsFromXCoordinate(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    input_x: JByteArray,
    output: JByteArray,
) -> jint {
    let hash_array = match jni_helpers::extract_random_seed(&env, &input_x) {
        Ok(value) => value,
        Err(value) => return value,
    };

    if group_id == GROUP1 {
        elements_from_hash_generic::<G1Config>(env, &hash_array, output)
    } else {
        elements_from_hash_generic::<G2Config>(env, &hash_array, output)
    }
}

/// JNI function that determines if a byte array representation of a group element is valid
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `value`   the byte that of size GROUP2_ELEMENT_AFFINE_SIZE represents the group element
/// # Returns
/// *   0    Success
/// *  BUSINESS_ERROR_POINT_NOT_IN_CURVE   Business Error: Point is not in the curve
/// *  A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsBytes(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    compress: jboolean,
    validate: jboolean,
    value: JByteArray,
    output: JByteArray,
) -> jint {
    let input_bytes = match jni_helpers::from_jbytearray_to_vec(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    match group_id {
        GROUP1 => {
            type G = G1;
            let point = match group_elements_deserialize_with_modes::<G>(&input_bytes, compress != 0, validate!=0) {
                Ok(a) => a,
                Err(_) =>  return BUSINESS_ERROR_POINT_NOT_IN_CURVE,
            };
            jni_helpers::serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = match group_elements_deserialize_with_modes::<G>(&input_bytes, compress !=0, validate!=0) {
                Ok(a) => a,
                Err(_) =>  return BUSINESS_ERROR_POINT_NOT_IN_CURVE,
            };
            jni_helpers::serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsCompressedBytes(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    value: JByteArray,
    output: JByteArray,
) -> jint {

    match group_id {
        GROUP1 => {
            type G = G1;
            let point = match to_point::<G>(&env, &value, false) {
                Ok(value) => value,
                Err(value) => return value,
            };
            jni_helpers::serialize_to_jbytearray_compress(env, &point, output).unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = match to_point::<G>(&env, &value, false) {
                Ok(value) => value,
                Err(value) => return value,
            };
            jni_helpers::serialize_to_jbytearray_compress(env, &point, output).unwrap_or_else(|value| value)
        }
    }
}


/// Returns the zero group element
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsZero(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    output: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            let point = group_elements_zero::<G>();
            jni_helpers::serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = group_elements_zero::<G>();
            jni_helpers::serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
        }
    }
}

/// Returns the Generator group element
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsGenerator(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    output: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            let point = group_elements_generator::<G>();
            jni_helpers::serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = group_elements_generator::<G>();
            jni_helpers::serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
        }
    }
}

/// returns if the two representations of a group element are the same
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `value`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element
/// * `value2`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element 2
/// # Returns
/// *   0    False
/// *   1    True
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsEquals(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    value: JByteArray,
    value2: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::compare_points::<G>(&env, &value, &value2)
        }
        _ => {
            type G = G2;
            jni_helpers::compare_points::<G>(&env, &value, &value2)
        }
    }
}

/// returns the size in bytes of a group element object representation
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// # Returns
/// *   the value of GROUP2_ELEMENT_SIZE constant
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsSize(
    _env: JNIEnv,
    _instance: JObject,
    group_id: jint,
) -> jint {
    match group_id {
        GROUP1 => GROUP1_ELEMENT_SIZE as jint,
        _ => GROUP2_ELEMENT_SIZE as jint,
    }
}

/// returns the sum of two representations of a group elements
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `value`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element
/// * `value2`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element 2
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns

/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsAdd(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    value: JByteArray,
    value2: JByteArray,
    output: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::add_points::<G>(env, &value, &value2, output)
        }
        _ => {
            type G = G2;
            jni_helpers::add_points::<G>(env, &value, &value2, output)
        }
    }
}

/// returns the multiplication of a group elements and a scalar
/// in this notation this is the power operation
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `value`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element
/// * `value2`  the byte that represents the scalar
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsScalarMul(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    value: JByteArray,
    value2: JByteArray,
    output: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::multiply_point_and_scalar::<G>(env, &value, &value2, output)
        }
        _ => {
            type G = G2;
            jni_helpers::multiply_point_and_scalar::<G>(env, &value, &value2, output)
        }
    }
}

/// JNI function to return the batch addition of N group elements
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `values`   the byte matrix that represents the collection of group elements
/// * `output`   the byte array that will be filled with the new point representing the result of the operation
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsBatchAdd(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    values: JObjectArray,
    output: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::total_sum_points::<G>(env, values, output)
        }
        _ => {
            type G = G2;
            jni_helpers::total_sum_points::<G>(env, values, output)
        }
    }
}

/// JNI function to return the multi scalar multiplication of each groupElement with its corresponding scalar
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `scalars`  the long array that represents the collection of scalars
/// * `values`   the byte matrix that represents the collection of group elements
/// * `output`   the byte array that will be filled with the new point representing the result of the operation
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsMsm__I_3J_3_3B_3B(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    scalars: JLongArray,
    values: JObjectArray,
    outputs: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::msm_scalars_longs::<G>(env, scalars, values, outputs)
        }
        _ => {
            type G = G2;
            jni_helpers::msm_scalars_longs::<G>(env, scalars, values, outputs)
        }
    }
}

/// JNI function to return the multi scalar multiplication of each groupElement with its corresponding scalar
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `scalars`  the byte matrix that represents the collection of scalars
/// * `values`   the byte matrix that represents the collection of group elements
/// * `output`   the byte array that will be filled with the new point representing the result of the operation
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsMsm__I_3_3B_3_3B_3B(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    scalars: JObjectArray,
    values: JObjectArray,
    outputs: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::msm_scalars::<G>(env, scalars, values, outputs)
        }
        _ => {
            type G = G2;
            jni_helpers::msm_scalars::<G>(env, scalars, values, outputs)
        }
    }
}

/// returns the multiplication of a group elements and a scalar
/// in this notation this is the power operation
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `value`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element
/// * `value2`  the byte that represents the scalar
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsLongMul(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    value: JByteArray,
    value2: jlong,
    output: JByteArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::multiply_point_and_scalar_long::<G>(env, &value, value2, output)
        }
        _ => {
            type G = G2;
            jni_helpers::multiply_point_and_scalar_long::<G>(env, &value, value2, output)
        }
    }
}
