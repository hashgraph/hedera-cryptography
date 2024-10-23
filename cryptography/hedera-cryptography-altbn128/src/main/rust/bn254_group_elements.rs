 use ark_bn254::{G1Affine, G2Affine};
use crate::group_element_utils::*;
use crate::jni_helpers;
use jni::objects::{JByteArray, JObject, JObjectArray};
use jni::sys::jint;
use jni::JNIEnv;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;
use crate::jni_helpers::{G1, G2};
const GROUP1_ELEMENT_SIZE: usize = 64;
const GROUP2_ELEMENT_SIZE: usize = 128;
const GROUP1: i32 = 0;

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
            jni_helpers::write_return_point::<G>(env, &point, output).unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = group_elements_from_random::<G, ChaCha8Rng>(&mut rng);
            jni_helpers::write_return_point::<G>(env, &point, output).unwrap_or_else(|value| value)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsFromHash(
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
        let x = x_coordinate_from_hash::<G1>(&hash_array).unwrap();
        let point = point_from_x::<ark_bn254::g1::Config>(x).unwrap();
        jni_helpers::write_return_point::<G1Affine>(env, &point, output).unwrap_or_else(|value| value)

    } else {
        let x = x_coordinate_from_hash::<G2>(&hash_array).unwrap();
        let point = point_from_x::<ark_bn254::g2::Config>(x).unwrap();
        jni_helpers::write_return_point::<G2Affine>(env, &point, output).unwrap_or_else(|value| value)
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
    value: JByteArray,
) -> jint {
    let input_bytes = match jni_helpers::from_jbytearray_to_vec(env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    match group_id {
        GROUP1 => jni_helpers::validate_g1point(&input_bytes),
        _ => jni_helpers::validate_g2point(&input_bytes),
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
            jni_helpers::write_return_point(env, &point, output).unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = group_elements_zero::<G>();
            jni_helpers::write_return_point(env, &point, output).unwrap_or_else(|value| value)
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
            jni_helpers::write_return_point(env, &point, output).unwrap_or_else(|value| value)
        }
        _ => {
            type G = G2;
            let point = group_elements_generator::<G>();
            jni_helpers::write_return_point(env, &point, output).unwrap_or_else(|value| value)
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

/// JNI function to return the batch multiplication of the group generator with N scalars
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
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_groupElementsBatchScalarMul(
    env: JNIEnv,
    _instance: JObject,
    group_id: jint,
    values: JObjectArray,
    outputs: JObjectArray,
) -> jint {
    match group_id {
        GROUP1 => {
            type G = G1;
            jni_helpers::batch_multiply_points::<G>(env, values, outputs)
        }
        _ => {
            type G = G2;
            jni_helpers::batch_multiply_points::<G>(env, values, outputs)
        }
    }
}
