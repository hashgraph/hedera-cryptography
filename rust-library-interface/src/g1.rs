use std::convert::TryInto;

use bls12_381::*;
use group::{Curve, Group};
use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::{jbyteArray, jobject, jobjectArray};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use crate::common::*;
use crate::scalar::scalar_from_jobject;

/// Converts a g1 jobject to a G1Affine object
pub(crate) fn g1_from_jobject(env: &JNIEnv, object: &jobject) -> Result<G1Affine, GenericError> {
    let compressed = env.get_field(*object, "compressed", "Z")?.z()?;
    let g1_bytes = env
        .get_field(*object, "groupElement", "[B")?
        .l()?
        .into_inner();

    if compressed {
        Ok(from_bytes_generic(
            &env,
            &g1_bytes,
            &G1Affine::from_compressed,
        )?)
    } else {
        Ok(from_bytes_generic(
            &env,
            &g1_bytes,
            &G1Affine::from_uncompressed,
        )?)
    }
}

/// Creates a new identity element of group g1
#[no_mangle]
pub extern "system" fn newG1Identity(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    let new_identity: G1Affine = Default::default();

    create_output(&env, &new_identity.to_uncompressed())
}

/// Internal
fn g1_element_equals(
    env: &JNIEnv,
    g1_1_object: &jobject,
    g1_2_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let g1_1 = g1_from_jobject(&env, g1_1_object)?;
    let g1_2 = g1_from_jobject(&env, g1_2_object)?;

    Ok(create_output(&env, if g1_1 == g1_2 { &[1] } else { &[0] }))
}

/// Checks if 2 g1 elements are equal
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_g1ElementEquals(
    env: JNIEnv,
    _class: JClass,
    g1_1_object: jobject,
    g1_2_object: jobject,
) -> jbyteArray {
    match g1_element_equals(&env, &g1_1_object, &g1_2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Checks if a g1 element is valid
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_checkG1Validity(
    env: JNIEnv,
    _class: JClass,
    g1_object: jobject,
) -> jbyteArray {
    match g1_from_jobject(&env, &g1_object) {
        Ok(_) => create_output(&env, &[1]),
        Err(_) => {
            return create_output(&env, &[0])
        }
    }
}

/// Internal
fn new_g1_from_bytes(
    env: &JNIEnv,
    input_seed_bytes: &jbyteArray,
) -> Result<jbyteArray, GenericError> {
    let seed_vector: Vec<u8> = env.convert_byte_array(*input_seed_bytes)?;
    let seed_array = seed_vector.try_into()?;

    let new_random_element: G1Projective = G1Projective::random(ChaChaRng::from_seed(seed_array));

    Ok(create_output(
        &env,
        &G1Affine::from(new_random_element).to_uncompressed(),
    ))
}

/// Creates a new g1 element based on a byte array seed
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_newRandomG1(
    env: JNIEnv,
    _class: JClass,
    input_seed_bytes: jbyteArray,
) -> jbyteArray {
    match new_g1_from_bytes(&env, &input_seed_bytes) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g1_divide(
    env: &JNIEnv,
    g1_1_object: &jobject,
    g1_2_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let g1_1 = g1_from_jobject(&env, &g1_1_object)?;
    let g1_2 = g1_from_jobject(&env, &g1_2_object)?;

    // BLS12_381 library defines math operations differently, hence the use of `-` here instead of `/`
    // The name of this function was chosen to maintain consistency with terminology used in javaland
    let quotient: G1Projective = g1_1 - G1Projective::from(g1_2);

    Ok(create_output(
        &env,
        &G1Affine::from(quotient).to_uncompressed(),
    ))
}

/// Computes the quotient of 2 group elements of g1
/// Result is an element of g1
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_g1Divide(
    env: JNIEnv,
    _class: JClass,
    g1_1_object: jobject,
    g1_2_object: jobject,
) -> jbyteArray {
    match g1_divide(&env, &g1_1_object, &g1_2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g1_multiply(
    env: &JNIEnv,
    g1_1_object: &jobject,
    g1_2_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let g1_1 = g1_from_jobject(&env, &g1_1_object)?;
    let g1_2 = g1_from_jobject(&env, &g1_2_object)?;

    // BLS12_381 library defines math operations differently, hence the use of `+` here instead of `*`
    // The name of this function was chosen to maintain consistency with terminology used in javaland
    let product: G1Projective = g1_1 + G1Projective::from(g1_2);

    Ok(create_output(
        &env,
        &G1Affine::from(product).to_uncompressed(),
    ))
}

/// Computes the product of 2 group elements of g1
/// Result is an element of g1
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_g1Multiply(
    env: JNIEnv,
    _class: JClass,
    g1_1_object: jobject,
    g1_2_object: jobject,
) -> jbyteArray {
    match g1_multiply(&env, &g1_1_object, &g1_2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g1_batch_multiply(
    env: &JNIEnv,
    element_batch: &jobjectArray,
) -> Result<jbyteArray, GenericError> {
    let element_batch_len = env.get_array_length(*element_batch)?;

    if element_batch_len < 2 {
        return Err(GenericError::ArraySize(
            "Input batch must have at least 2 elements".to_owned(),
        ));
    }

    let mut product = G1Projective::identity();

    for index in 0..element_batch_len {
        let g1_object = env.get_object_array_element(*element_batch, index)?;
        let g1 = g1_from_jobject(&env, &g1_object.into_inner())?;

        product = product + g1;
    }

    Ok(create_output(&env, &product.to_affine().to_uncompressed()))
}

/// Computes the product of a batch of group elements of g1
/// Result is an element of g1
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_g1BatchMultiply(
    env: JNIEnv,
    _class: JClass,
    element_batch: jobjectArray,
) -> jbyteArray {
    match g1_batch_multiply(&env, &element_batch) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g1_pow_zn(
    env: &JNIEnv,
    base_object: &jobject,
    exponent_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let base = g1_from_jobject(&env, base_object)?;
    let exponent = scalar_from_jobject(&env, exponent_object)?;

    // BLS12_381 library defines math operations differently, hence the use of `*` here instead of `^`
    // The name of this function was chosen to maintain consistency with terminology used in javaland
    let power: G1Projective = base * exponent;

    Ok(create_output(
        &env,
        &G1Affine::from(power).to_uncompressed(),
    ))
}

/// Computes the value of a g1 group element, taken to the power of a scalar
/// Result is an element of g1
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_g1PowZn(
    env: JNIEnv,
    _class: JClass,
    base_object: jobject,     // g1
    exponent_object: jobject, // scalar
) -> jbyteArray {
    match g1_pow_zn(&env, &base_object, &exponent_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Compresses a group element
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group1Bindings_g1Compress(
    env: JNIEnv,
    _class: JClass,
    element_object: jobject,
) -> jbyteArray {
    let element = match g1_from_jobject(&env, &element_object) {
        Ok(base) => base,
        Err(error) => return set_error_and_expect(&env, error.get_error_code()),
    };

    create_output(&env, &element.to_compressed())
}
