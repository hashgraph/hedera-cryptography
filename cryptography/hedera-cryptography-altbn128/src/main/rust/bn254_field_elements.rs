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

use crate::jni_helpers;
use crate::jni_helpers::{batch_add_scalars, batch_multiply_scalars};
use crate::scalars_utils::*;
use jni::objects::{JByteArray, JLongArray, JObject, JObjectArray};
use jni::sys::{jint, jlong};
use jni::JNIEnv;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

const FIELD_ELEMENT_SIZE: usize = 32;
/// * -5    Business Error: Scalar can not be inverted
const BUSINESS_ERROR_CANNOT_PERFORM_INVERSE_OPERATION: i32 = -5;

/// JNI function to create a new random scalar from a seed value
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input_seed` the byte seed to be used to create the new scalar. Must be size SEED_SIZE.
/// * `output`  the byte array that will be filled with the new scalar. Must be size FIELD_ELEMENT_SIZE.
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsFromRandomSeed(
    env: JNIEnv,
    _instance: JObject,
    input_seed: JByteArray,
    output: JByteArray,
) -> jint {
    let seed_array = match jni_helpers::extract_random_seed(&env, &input_seed) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let mut rng = ChaCha8Rng::from_seed(seed_array);

    let scalar = scalars_from_random::<ChaCha8Rng>(&mut rng);

    jni_helpers::write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}

/// JNI function to create a new scalar from a long
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input_long`  the long to be used to create the new scalar
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsFromLong(
    env: JNIEnv,
    _instance: JObject,
    input_long: jlong,
    output: JByteArray,
) -> jint {
    let scalar = scalars_from_i64(input_long as i64);
    jni_helpers::write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}

/// JNI function to create a new scalar from a byte array
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input`  the byte that represents the scalar
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsFromBytes(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    output: JByteArray,
) -> jint {
    let scalar = match jni_helpers::to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    jni_helpers::write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}

/// JNI function to create a zero value scalar
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsZero(
    env: JNIEnv,
    _instance: JObject,
    output: JByteArray,
) -> jint {
    let scalar = scalars_zero();
    jni_helpers::write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}

/// JNI function to create a one value scalar
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsOne(
    env: JNIEnv,
    _instance: JObject,
    output: JByteArray,
) -> jint {
    let scalar = scalars_one();
    jni_helpers::write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}

/// JNI function to return if the two representations of a field element are the same
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `value`   the byte that represents the scalar 1
/// * `value2`  the byte that represents the scalar 2
/// # Returns
/// *   0    False
/// *   1    True
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsEquals(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
) -> jint {
    let scalar = match jni_helpers::to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match jni_helpers::to_scalar(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    (scalar == scalar2) as jint
}

/// JNI function to returns the size in bytes of a field element object representation
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// # Returns
/// *   the value of FIELD_ELEMENT_SIZE constant
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsSize(
    _env: JNIEnv,
    _instance: JObject,
) -> jint {
    FIELD_ELEMENT_SIZE as jint
}

/// JNI function to add the value of two scalars
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `value`   the byte that represents the scalar 1
/// * `value2`  the byte that represents the scalar 2
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsAdd(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
    output: JByteArray,
) -> jint {
    let scalar1 = match jni_helpers::to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match jni_helpers::to_scalar(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar = scalars_add(scalar1, scalar2);
    jni_helpers::write_return_scalar(env, output, scalar).unwrap()
}

/// JNI function to subtract the value of two scalars
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `value`   the byte that represents the scalar 1
/// * `value2`  the byte that represents the scalar 2
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsSubtract(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
    output: JByteArray,
) -> jint {
    let scalar1 = match jni_helpers::to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match jni_helpers::to_scalar(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar = scalars_minus(scalar1, scalar2);
    jni_helpers::write_return_scalar(env, output, scalar).unwrap()
}

/// JNI function to multiply the value of two scalars
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `value`   the byte that represents the scalar 1
/// * `value2`  the byte that represents the scalar 2
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsMultiply(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
    output: JByteArray,
) -> jint {
    let scalar1 = match jni_helpers::to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match jni_helpers::to_scalar(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar = scalars_multiply(scalar1, scalar2);
    jni_helpers::write_return_scalar(env, output, scalar).unwrap()
}

/// JNI function to invert a scalar represented in a byte array
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input`  the byte that represents the scalar
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsInverse(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    output: JByteArray,
) -> jint {
    let scalar1 = match jni_helpers::to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let scalar = match scalars_inverse(scalar1) {
        Ok(val) => val,
        Err(_) => return BUSINESS_ERROR_CANNOT_PERFORM_INVERSE_OPERATION,
    };
    jni_helpers::write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}

/// JNI function to produce the pow operation between a scalar represented in a byte array and a long exponent
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input`  the byte that represents the scalar
/// * `exponent`  the long to be used as exponent
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsPow(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    exponent: jlong,
    output: JByteArray,
) -> jint {
    let scalar1 = match jni_helpers::to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let scalar = scalars_pow(scalar1, exponent as u64);
    jni_helpers::write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}

/// JNI function to return the batch multiplication of the group generator with N scalars
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `scalars`   the long array that represents the collection of scalars
/// * `values`   the byte matrix that represents the collection of group elements
/// * `output`   the byte array that will be filled with the new point representing the result of the operation
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsBatchMul(
    env: JNIEnv,
    _instance: JObject,
    scalars: JLongArray,
    output: JByteArray,
) -> jint {
    batch_multiply_scalars(env, scalars, output)
}

/// JNI function to return the batch addition of a list of N scalars
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `values`   the byte matrix that represents the collection of scalar values
/// * `output`   the byte array that will be filled with the result of the operation
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsBatchAdd(
    env: JNIEnv,
    _instance: JObject,
    values: JObjectArray,
    output: JByteArray,
) -> jint {
    batch_add_scalars(env, values, output)
}
