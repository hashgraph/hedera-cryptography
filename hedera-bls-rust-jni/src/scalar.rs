use std::convert::TryInto;
use std::mem;

use bls12_381::*;
use ff::Field;
use jni::JNIEnv;
use jni::objects::{JClass, JObject};
use jni::sys::{jbyte, jbyteArray, jint};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use crate::common::*;

const BIG_INT_SIZE: usize = 32;

/// Converts a scalar jobject to a Scalar object
pub(crate) fn scalar_from_jobject(env: &JNIEnv, object: &JObject) -> Result<Scalar, GenericError> {
    let scalar_bytes = env
        .get_field(*object, "fieldElement", "[B")?
        .l()?
        .into_raw();

    Ok(from_bytes_generic(
        &env,
        &scalar_bytes,
        &Scalar::from_bytes,
    )?)
}

/// Converts bytes to a big int, which is represented by an array of 4 64 bit integers
fn bytes_to_big_int(env: &JNIEnv, bytes: &jbyteArray) -> Result<[u64; 4], GenericError> {
    let mut vector: Vec<u8> = env.convert_byte_array(*bytes)?;

    if vector.len() > BIG_INT_SIZE {
        return Err(GenericError::InputLength(format!(
            "Input byte length {} is too long for a big int (max {} bytes)",
            vector.len(),
            BIG_INT_SIZE
        )));
    }

    // big integer from java comes in as big endian, with variable length
    vector.reverse(); // reverse bytes
    vector.resize(BIG_INT_SIZE, 0); // pad to length of 32

    let x1 = u64::from_le_bytes(<[u8; 8]>::try_from(&vector[0..8])?);
    let x2 = u64::from_le_bytes(<[u8; 8]>::try_from(&vector[8..16])?);
    let x3 = u64::from_le_bytes(<[u8; 8]>::try_from(&vector[16..24])?);
    let x4 = u64::from_le_bytes(<[u8; 8]>::try_from(&vector[24..32])?);

    Ok([x1, x2, x3, x4])
}

/// Creates a new scalar, based on input bytes
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_newRandomScalar(
    env: JNIEnv,
    _class: JClass,
    input_seed_bytes: jbyteArray,
    output: jbyteArray,
) -> jint {
    let seed_vector = match env.convert_byte_array(input_seed_bytes) {
        Ok(val) => val,
        Err(_) => return 1
    };

    let seed_array = match seed_vector.try_into() {
        Ok(val) => val,
        Err(_) => return 1
    };

    let random_scalar: &[jbyte; 32] = unsafe { mem::transmute(&Scalar::random(ChaChaRng::from_seed(seed_array)).to_bytes()) };

    return match env.set_byte_array_region(output, 0, random_scalar) {
        Ok(_) => 0,
        Err(_) => 1
    };
}

/// Creates a new scalar from an integer
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_newScalarFromInt(
    env: JNIEnv,
    _class: JClass,
    input_int: jint,
    output: jbyteArray,
) -> jint {
    let scalar: &[jbyte; 32] = unsafe { mem::transmute(&Scalar::from(input_int as u64).to_bytes()) };

    return match env.set_byte_array_region(output, 0, scalar) {
        Ok(_) => 0,
        Err(_) => 1
    };
}

/// Creates a new 0 value scalar
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_newZeroScalar(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    create_output(&env, &Scalar::zero().to_bytes())
}

/// Creates a new 1 value scalar
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_newOneScalar(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    create_output(&env, &Scalar::one().to_bytes())
}

/// Internal
fn scalar_equals(
    env: &JNIEnv,
    scalar1_object: &JObject,
    scalar2_object: &JObject,
) -> Result<jbyteArray, GenericError> {
    let scalar1 = scalar_from_jobject(&env, &scalar1_object)?;
    let scalar2 = scalar_from_jobject(&env, &scalar2_object)?;

    Ok(create_output(
        &env,
        if scalar1 == scalar2 { &[1] } else { &[0] },
    ))
}

/// Checks if 2 scalar values are equal
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_scalarEquals(
    env: JNIEnv,
    _class: JClass,
    scalar1_object: JObject,
    scalar2_object: JObject,
) -> jbyteArray {
    match scalar_equals(&env, &scalar1_object, &scalar2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}

/// Checks if a scalar is valid
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_checkScalarValidity(
    env: JNIEnv,
    _class: JClass,
    scalar_object: JObject,
) -> jbyteArray {
    match scalar_from_jobject(&env, &scalar_object) {
        Ok(_) => create_output(&env, &[1]),
        Err(_) => {
            return create_output(&env, &[0]);
        }
    }
}

/// Internal
fn scalar_add(
    env: &JNIEnv,
    scalar1_object: &JObject,
    scalar2_object: &JObject,
) -> Result<jbyteArray, GenericError> {
    let scalar1 = scalar_from_jobject(&env, &scalar1_object)?;
    let scalar2 = scalar_from_jobject(&env, &scalar2_object)?;

    Ok(create_output(&env, &(scalar1 + scalar2).to_bytes()))
}

/// Computes the sum of 2 scalar values
/// Result is a scalar
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_scalarAdd(
    env: JNIEnv,
    _class: JClass,
    scalar1_object: JObject,
    scalar2_object: JObject,
) -> jbyteArray {
    match scalar_add(&env, &scalar1_object, &scalar2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}

/// Internal
fn scalar_subtract(
    env: &JNIEnv,
    scalar1_object: &JObject,
    scalar2_object: &JObject,
) -> Result<jbyteArray, GenericError> {
    let scalar1 = scalar_from_jobject(&env, &scalar1_object)?;
    let scalar2 = scalar_from_jobject(&env, &scalar2_object)?;

    Ok(create_output(&env, &(scalar1 - scalar2).to_bytes()))
}

/// Computes the difference between 2 scalar values
/// Result is a scalar
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_scalarSubtract(
    env: JNIEnv,
    _class: JClass,
    scalar1_object: JObject,
    scalar2_object: JObject,
) -> jbyteArray {
    match scalar_subtract(&env, &scalar1_object, &scalar2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}

/// Internal
fn scalar_multiply(
    env: &JNIEnv,
    scalar1_object: &JObject,
    scalar2_object: &JObject,
) -> Result<jbyteArray, GenericError> {
    let scalar1 = scalar_from_jobject(&env, &scalar1_object)?;
    let scalar2 = scalar_from_jobject(&env, &scalar2_object)?;

    Ok(create_output(&env, &(scalar1 * scalar2).to_bytes()))
}

/// Computes the product of 2 scalar values
/// Result is a scalar
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_scalarMultiply(
    env: JNIEnv,
    _class: JClass,
    scalar1_object: JObject,
    scalar2_object: JObject,
) -> jbyteArray {
    match scalar_multiply(&env, &scalar1_object, &scalar2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}

/// Internal
fn scalar_divide(
    env: &JNIEnv,
    scalar1_object: &JObject,
    scalar2_object: &JObject,
) -> Result<jbyteArray, GenericError> {
    let scalar1 = scalar_from_jobject(&env, &scalar1_object)?;
    let scalar2 = scalar_from_jobject(&env, &scalar2_object)?;

    let scalar2_inversion: Scalar = Option::from(scalar2.invert())
        .ok_or_else(|| GenericError::Computation("BLS12_381 lib invert() failure".to_owned()))?;

    Ok(create_output(
        &env,
        &(scalar1 * scalar2_inversion).to_bytes(),
    ))
}

/// Computes the quotient of 2 scalar values
/// Result is a scalar
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_scalarDivide(
    env: JNIEnv,
    _class: JClass,
    scalar1_object: JObject,
    scalar2_object: JObject,
) -> jbyteArray {
    match scalar_divide(&env, &scalar1_object, &scalar2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}

/// Internal
fn scalar_power(
    env: &JNIEnv,
    base_object: &JObject,
    exponent_bytes: &jbyteArray,
) -> Result<jbyteArray, GenericError> {
    let base = scalar_from_jobject(&env, &base_object)?;
    let exponent = bytes_to_big_int(&env, exponent_bytes)?;

    Ok(create_output(&env, &(base.pow(&exponent)).to_bytes()))
}

/// Computes the value of a scalar taken to the power of a big integer
/// Result is a scalar value
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381ScalarBindings_scalarPower(
    env: JNIEnv,
    _class: JClass,
    base_object: JObject,       // scalar
    exponent_bytes: jbyteArray, // big int
) -> jbyteArray {
    match scalar_power(&env, &base_object, &exponent_bytes) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}
