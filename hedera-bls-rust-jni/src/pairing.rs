use bls12_381::*;
use jni::JNIEnv;
use jni::objects::{JClass, JObject};
use jni::sys::jbyteArray;

use crate::common::*;
use crate::g1::g1_from_jobject;
use crate::g2::g2_from_jobject;

/// Internal
fn compare_pairing(
    env: &JNIEnv,
    g1_a_object: &JObject,
    g2_a_object: &JObject,
    g1_b_object: &JObject,
    g2_b_object: &JObject,
) -> Result<jbyteArray, GenericError> {
    let g1_a = g1_from_jobject(&env, &g1_a_object)?;
    let g2_a = g2_from_jobject(&env, &g2_a_object)?;
    let g1_b = g1_from_jobject(&env, &g1_b_object)?;
    let g2_b = g2_from_jobject(&env, &g2_b_object)?;

    Ok(create_output(
        &env,
        if pairing(&g1_a, &g2_a) == pairing(&g1_b, &g2_b) {
            &[1]
        } else {
            &[0]
        },
    ))
}

/// Computes 2 pairings, A and B, and checks for equality of the pairing outputs
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381PairingBindings_comparePairing(
    env: JNIEnv,
    _class: JClass,
    g1_a_object: JObject,
    g2_a_object: JObject,
    g1_b_object: JObject,
    g2_b_object: JObject,
) -> jbyteArray {
    match compare_pairing(&env, &g1_a_object, &g2_a_object, &g1_b_object, &g2_b_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}

/// Internal
fn pairing_display(
    env: &JNIEnv,
    g1_object: &JObject,
    g2_object: &JObject,
) -> Result<jbyteArray, GenericError> {
    let g1 = g1_from_jobject(&env, &g1_object)?;
    let g2 = g2_from_jobject(&env, &g2_object)?;

    Ok(create_output(
        &env,
        format!("{}", pairing(&g1, &g2)).as_bytes(),
    ))
}

/// Accepts an element from group1, and an element from group2
/// Computes the pairing of the two group elements
/// Returns a string (as a byte array) representing the resulting group element
#[no_mangle]
pub extern "system" fn Java_com_hedera_platform_bls_BLS12381PairingBindings_pairingDisplay(
    env: JNIEnv,
    _class: JClass,
    g1_object: JObject,
    g2_object: JObject,
) -> jbyteArray {
    match pairing_display(&env, &g1_object, &g2_object) {
        Ok(output) => output,
        Err(error) => {
            return set_error_and_expect(&env, GenericError::from(error).get_error_code());
        }
    }
}
