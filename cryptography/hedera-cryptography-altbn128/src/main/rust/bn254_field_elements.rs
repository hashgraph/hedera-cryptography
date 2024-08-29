use crate::scalars_utils::*;
use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyte, jint, jlong};
use jni::JNIEnv;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

const SEED_SIZE: usize = 32;
const FIELD_ELEMENT_SIZE: usize = 32;
/// * 0     False
/// * 1     True
/// * 0     Success
const SUCCESS: i32 = 0;
/// * -5    Business Error: Scalar can not be inverted
const BUSINESS_ERROR_CANNOT_PERFORM_INVERSE_OPERATION: i32 = -5;
/// * -1001  Jni Error: Could not convert argument array to vector
const JNI_ERROR_ARG_TO_VEC: i32 = -1001;
/// * -1002  Rust error: Could not convert argument vector to an unsigned byte array
const RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE: i32 = -1002;
/// * -1003   Ark Error: Result cannot be serialized
const ARK_ERROR_RESULT_SERIALIZATION: i32 = -1003;
/// * -1004  Jni Error: Could not set the scalar in the output byte array
const JNI_ERROR_COULD_NOT_SET_OUTPUT_BYTE_ARRAY: i32 = -1004;

/// Utility function read a scalar form a JbyteArray, if the scalar is bigger than the field a reduction is performed
fn to_scalar(env: &JNIEnv, value: &JByteArray) -> Result<F, i32> {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };

    let input_array: [u8; FIELD_ELEMENT_SIZE] = match input_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return Err(RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE),
    };
    let scalar = scalars_from_bytes(&input_array);
    Ok(scalar)
}

/// Utility function to write the serialized representation of a scalar in an existing JByteArray
fn write_return_scalar(env: JNIEnv, output: JByteArray, scalar: F) -> Result<jint, jint> {
    let fe_bytes = match scalars_to_bytes(scalar) {
        Ok(val) => val,
        Err(_) => return Err(ARK_ERROR_RESULT_SERIALIZATION),
    };

    let transformed_vec: Vec<jbyte> = fe_bytes.iter().map(|&x| x as jbyte).collect();

    let scalar_jbytes: [jbyte; FIELD_ELEMENT_SIZE] = match transformed_vec.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(ARK_ERROR_RESULT_SERIALIZATION),
    };

    Ok(match env.set_byte_array_region(output, 0, &scalar_jbytes) {
        Ok(_) => SUCCESS,
        Err(_) => JNI_ERROR_COULD_NOT_SET_OUTPUT_BYTE_ARRAY,
    })
}

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
    let input_seed_bytes = match env.convert_byte_array(&input_seed) {
        Ok(val) => val,
        Err(_) => return JNI_ERROR_ARG_TO_VEC,
    };

    let seed_array: [u8; SEED_SIZE] = match input_seed_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE,
    };

    let mut rng = ChaCha8Rng::from_seed(seed_array);

    let scalar = scalars_from_random::<ChaCha8Rng>(&mut rng);

    write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
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
    let scalar = scalars_from_u64(input_long as u64);
    write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
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
    let scalar = match to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
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
    write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
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
    write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
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
    let scalar = match to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match to_scalar(&env, &value2) {
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

/// returns the size in bytes of the random seed to use
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// # Returns
/// *   the value of SEED_SIZE constant
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsRandomSeedSize(
    _env: JNIEnv,
    _instance: JObject,
) -> jint {
    SEED_SIZE as jint
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
    let scalar1 = match to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match to_scalar(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar = scalars_add(scalar1, scalar2);
    write_return_scalar(env, output, scalar).unwrap()
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
    let scalar1 = match to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match to_scalar(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar = scalars_minus(scalar1, scalar2);
    write_return_scalar(env, output, scalar).unwrap()
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
    let scalar1 = match to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar2 = match to_scalar(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar = scalars_multiply(scalar1, scalar2);
    write_return_scalar(env, output, scalar).unwrap()
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
    let scalar1 = match to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let scalar = match scalars_inverse(scalar1) {
        Ok(val) => val,
        Err(_) => return BUSINESS_ERROR_CANNOT_PERFORM_INVERSE_OPERATION,
    };
    write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
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
    let scalar1 = match to_scalar(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let scalar = scalars_pow(scalar1, exponent as u64);
    write_return_scalar(env, output, scalar).unwrap_or_else(|value| value)
}
