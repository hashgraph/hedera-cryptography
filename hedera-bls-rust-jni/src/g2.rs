use std::convert::TryInto;

use bls12_381::*;
use group::{Curve, Group};
use jni::objects::JClass;
use jni::sys::{jbyteArray, jobject, jobjectArray};
use jni::JNIEnv;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use crate::common::*;
use crate::scalar::scalar_from_jobject;

/// Converts a g2 jobject to a G2Affine object
pub(crate) fn g2_from_jobject(env: &JNIEnv, object: &jobject) -> Result<G2Affine, GenericError> {
    let compressed = env.get_field(*object, "compressed", "Z")?.z()?;
    let g2_bytes = env
        .get_field(*object, "groupElement", "[B")?
        .l()?
        .into_inner();

    if compressed {
        Ok(from_bytes_generic(
            &env,
            &g2_bytes,
            &G2Affine::from_compressed,
        )?)
    } else {
        Ok(from_bytes_generic(
            &env,
            &g2_bytes,
            &G2Affine::from_uncompressed,
        )?)
    }
}

/// Creates a new identity element of group g2
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_newG2Identity(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    let new_identity: G2Affine = Default::default();

    create_output(&env, &new_identity.to_uncompressed())
}

/// Internal
fn g2_element_equals(
    env: &JNIEnv,
    g2_1_object: &jobject,
    g2_2_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let g2_1: G2Affine = g2_from_jobject(&env, g2_1_object)?;
    let g2_2: G2Affine = g2_from_jobject(&env, g2_2_object)?;

    Ok(create_output(&env, if g2_1 == g2_2 { &[1] } else { &[0] }))
}

/// Checks if 2 g2 elements are equal
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_g2ElementEquals(
    env: JNIEnv,
    _class: JClass,
    g2_1_object: jobject,
    g2_2_object: jobject,
) -> jbyteArray {
    match g2_element_equals(&env, &g2_1_object, &g2_2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Checks if a g2 element is valid
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_checkG2Validity(
    env: JNIEnv,
    _class: JClass,
    g2_object: jobject,
) -> jbyteArray {
    match g2_from_jobject(&env, &g2_object) {
        Ok(_) => create_output(&env, &[1]),
        Err(_) => {
            return create_output(&env, &[0])
        }
    }
}

/// Internal
fn new_g2_from_bytes(
    env: &JNIEnv,
    input_seed_bytes: &jbyteArray,
) -> Result<jbyteArray, GenericError> {
    let seed_vector = env.convert_byte_array(*input_seed_bytes)?;
    let seed_array = seed_vector.try_into()?;

    let new_random_element: G2Projective = G2Projective::random(ChaChaRng::from_seed(seed_array));

    Ok(create_output(
        &env,
        &G2Affine::from(new_random_element).to_uncompressed(),
    ))
}

/// Creates a new g2 element based on a byte array seed
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_newRandomG2(
    env: JNIEnv,
    _class: JClass,
    input_seed_bytes: jbyteArray,
) -> jbyteArray {
    match new_g2_from_bytes(&env, &input_seed_bytes) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g2_divide(
    env: &JNIEnv,
    g2_1_object: &jobject,
    g2_2_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let g2_1 = g2_from_jobject(&env, g2_1_object)?;
    let g2_2 = g2_from_jobject(&env, g2_2_object)?;

    // BLS12_381 library defines math operations differently, hence the use of `-` here instead of `/`
    // The name of this function was chosen to maintain consistency with terminology used in javaland
    let quotient: G2Projective = g2_1 - G2Projective::from(g2_2);

    Ok(create_output(
        &env,
        &G2Affine::from(quotient).to_uncompressed(),
    ))
}

/// Computes the quotient of 2 group elements of g2
/// Result is an element of g2
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_g2Divide(
    env: JNIEnv,
    _class: JClass,
    g2_1_object: jobject,
    g2_2_object: jobject,
) -> jbyteArray {
    match g2_divide(&env, &g2_1_object, &g2_2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g2_multiply(
    env: &JNIEnv,
    g2_1_object: &jobject,
    g2_2_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let g2_1 = g2_from_jobject(&env, g2_1_object)?;
    let g2_2 = g2_from_jobject(&env, g2_2_object)?;

    // BLS12_381 library defines math operations differently, hence the use of `+` here instead of `*`
    // The name of this function was chosen to maintain consistency with terminology used in javaland
    let product: G2Projective = g2_1 + G2Projective::from(g2_2);

    Ok(create_output(
        &env,
        &G2Affine::from(product).to_uncompressed(),
    ))
}

/// Computes the product of 2 group elements of g2
/// Result is an element of g2
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_g2Multiply(
    env: JNIEnv,
    _class: JClass,
    g2_1_object: jobject,
    g2_2_object: jobject,
) -> jbyteArray {
    match g2_multiply(&env, &g2_1_object, &g2_2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g2_batch_multiply(
    env: &JNIEnv,
    element_batch: &jobjectArray,
) -> Result<jbyteArray, GenericError> {
    let element_batch_len = env.get_array_length(*element_batch)?;

    if element_batch_len < 2 {
        return Err(GenericError::ArraySize(
            "Input batch must have at least 2 elements".to_owned(),
        ));
    }

    let mut product = G2Projective::identity();

    for index in 0..element_batch_len {
        let g2_object = env.get_object_array_element(*element_batch, index)?;
        let g2 = g2_from_jobject(&env, &g2_object.into_inner())?;

        product = product + g2;
    }

    Ok(create_output(&env, &product.to_affine().to_uncompressed()))
}

/// Computes the product of a batch of group elements of g2
/// Result is an element of g2
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_g2BatchMultiply(
    env: JNIEnv,
    _class: JClass,
    element_batch: jobjectArray,
) -> jbyteArray {
    match g2_batch_multiply(&env, &element_batch) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Internal
fn g2_pow_zn(
    env: &JNIEnv,
    base_object: &jobject,
    exponent_object: &jobject,
) -> Result<jbyteArray, GenericError> {
    let base = g2_from_jobject(&env, base_object)?;
    let exponent = scalar_from_jobject(&env, exponent_object)?;

    // BLS12_381 library defines math operations differently, hence the use of `*` here instead of `^`
    // The name of this function was chosen to maintain consistency with terminology used in javaland
    let power: G2Projective = base * exponent;

    Ok(create_output(
        &env,
        &G2Affine::from(power).to_uncompressed(),
    ))
}

/// Computes the value of a g2 group element, taken to the power of a scalar
/// Result is an element of g2
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_g2PowZn(
    env: JNIEnv,
    _class: JClass,
    base_object: jobject,     // g2
    exponent_object: jobject, // scalar
) -> jbyteArray {
    match g2_pow_zn(&env, &base_object, &exponent_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code())
        }
    }
}

/// Compresses a group element
#[no_mangle]
pub extern "system" fn Java_com_hedera_bls_BLS12381Group2Bindings_g2Compress(
    env: JNIEnv,
    _class: JClass,
    element_object: jobject,
) -> jbyteArray {
    let element = match g2_from_jobject(&env, &element_object) {
        Ok(base) => base,
        Err(error) => return set_error_and_expect(&env, error.get_error_code()),
    };

    create_output(&env, &element.to_compressed())
}
