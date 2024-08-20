use crate::scalars_utils::*;
use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyte, jint, jlong};
use jni::JNIEnv;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

const SEED_SIZE: usize = 32;
const FIELD_ELEMENT_SIZE: usize = 32;

/// JNI function to create a new random scalar from a seed value
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A jint indicating the elliptic curve group to use.
/// * `input_seed` the byte seed to be used to create the new scalar. Must be size SEED_SIZE.
/// * `output`  the byte array that will be filled with the new scalar. Must be size FIELD_ELEMENT_SIZE.
/// # Returns
/// *   0    Success
/// * -1000  Jni Error: Could not convert group_assignment array to an int representation
/// * -1001  Jni Error: Could not convert input_seed array to vector
/// * -1002  Rust error: Could not convert input_seed vector to an unsigned byte array of size SEED_SIZE
/// * -1003  Rust error: Could not convert output vector to a jByte array of size FIELD_ELEMENT_SIZE
/// * -1004  Jni Error: Could not set the scalar in the output byte array
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsFromRandomSeed(
    env: JNIEnv,
    _instance: JObject,
    group_assignment: jint,
    input_seed: JByteArray,
    output: JByteArray,
) -> jint {
    let group_byte = match u8::try_from(group_assignment) {
        Ok(val) => val,
        Err(_) => return -1000,
    };

    let input_seed_bytes = match env.convert_byte_array(&input_seed) {
        Ok(val) => val,
        Err(_) => return -1001,
    };

    let seed_array: [u8; SEED_SIZE] = match input_seed_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return -1002,
    };

    let mut rng = ChaCha8Rng::from_seed(seed_array);

    let fe_bytes = match group_byte {
        0 => {
            let random_scalar =
                scalars_from_random::<ark_bn254::G2Projective, ChaCha8Rng>(&mut rng);
            scalars_to_bytes::<ark_bn254::G2Projective>(random_scalar)
        }
        _ => {
            let random_scalar =
                scalars_from_random::<ark_bn254::G1Projective, ChaCha8Rng>(&mut rng);
            scalars_to_bytes::<ark_bn254::G1Projective>(random_scalar)
        }
    };

    let transformed_vec: Vec<jbyte> = fe_bytes.iter().map(|&x| x as jbyte).collect();

    let scalar_jbytes: [jbyte; FIELD_ELEMENT_SIZE] = match transformed_vec.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return -1003,
    };

    match env.set_byte_array_region(output, 0, &scalar_jbytes) {
        Ok(_) => 0,
        Err(_) => -1004,
    }
}

/// JNI function to create a new scalar from a long
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A jint indicating the elliptic curve group to use.
/// * `input_long`  the long to be used to create the new scalar
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * -1000  Jni Error: Could not convert group_assignment array to an int representation
/// * -1003  Rust error: Could not convert output vector to a jByte array of size FIELD_ELEMENT_SIZE
/// * -1004  Jni Error: Could not set the scalar in the output byte array
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsFromLong(
    env: JNIEnv,
    _instance: JObject,
    group_assignment: jint,
    input_long: jlong,
    output: JByteArray,
) -> jint {
    let group_byte = match u8::try_from(group_assignment) {
        Ok(val) => val,
        Err(_) => return -1000,
    };

    let fe_bytes = match group_byte {
        0 => {
            let scalar = scalars_from_u64::<ark_bn254::G2Projective>(input_long as u64);
            scalars_to_bytes::<ark_bn254::G2Projective>(scalar)
        }
        _ => {
            let scalar = scalars_from_u64::<ark_bn254::G1Projective>(input_long as u64);
            scalars_to_bytes::<ark_bn254::G1Projective>(scalar)
        }
    };

    let transformed_vec: Vec<jbyte> = fe_bytes.iter().map(|&x| x as jbyte).collect();

    let scalar_jbytes: [jbyte; FIELD_ELEMENT_SIZE] = match transformed_vec.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return -1003,
    };

    match env.set_byte_array_region(output, 0, &scalar_jbytes) {
        Ok(_) => 0,
        Err(_) => -1004,
    }
}

/// JNI function to create a new scalar from a byte array
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A jint indicating the elliptic curve group to use.
/// * `input`  the byte that represents the scalar
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * -1000  Jni Error: Could not convert group_assignment array to an int representation
/// * -1001  Jni Error: Could not convert input_seed array to vector
/// * -1002  Rust error: Could not convert input vector to an unsigned byte array of size FIELD_ELEMENT_SIZE
/// * -1003  Rust error: Could not convert output vector to a jByte array of size FIELD_ELEMENT_SIZE
/// * -1004  Jni Error: Could not set the scalar in the output byte array
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsFromBytes(
    env: JNIEnv,
    _instance: JObject,
    group_assignment: jint,
    input: JByteArray,
    output: JByteArray,
) -> jint {
    let group_byte = match u8::try_from(group_assignment) {
        Ok(val) => val,
        Err(_) => return -1000,
    };

    let input_bytes = match env.convert_byte_array(&input) {
        Ok(val) => val,
        Err(_) => return -1001,
    };

    let input_array: [u8; FIELD_ELEMENT_SIZE] = match input_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return -1002,
    };

    let scalar = match group_byte {
        0 => {
            let scalar = scalars_from_bytes::<ark_bn254::G2Projective>(&input_array);
            scalars_to_bytes::<ark_bn254::G2Projective>(scalar)
        }
        _ => {
            let scalar = scalars_from_bytes::<ark_bn254::G1Projective>(&input_array);
            scalars_to_bytes::<ark_bn254::G1Projective>(scalar)
        }
    };

    let transformed_vec: Vec<jbyte> = scalar.iter().map(|&x| x as jbyte).collect();

    let scalar_jbytes: [jbyte; FIELD_ELEMENT_SIZE] = match transformed_vec.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return -1003,
    };

    match env.set_byte_array_region(output, 0, &scalar_jbytes) {
        Ok(_) => 0,
        Err(_) => -1004,
    }
}

/// Creates a zero value scalar
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A jint indicating the elliptic curve group to use.
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * -1000  Jni Error: Could not convert group_assignment array to an int representation
/// * -1003  Rust error: Could not convert output vector to a jByte array of size FIELD_ELEMENT_SIZE
/// * -1004  Jni Error: Could not set the scalar in the output byte array
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsZero(
    env: JNIEnv,
    _instance: JObject,
    group_assignment: jint,
    output: JByteArray,
) -> jint {
    let group_byte = match u8::try_from(group_assignment) {
        Ok(val) => val,
        Err(_) => return -1000,
    };

    let fe_bytes = match group_byte {
        0 => {
            let scalar = scalars_zero::<ark_bn254::G2Projective>();
            scalars_to_bytes::<ark_bn254::G2Projective>(scalar)
        }
        _ => {
            let scalar = scalars_zero::<ark_bn254::G1Projective>();
            scalars_to_bytes::<ark_bn254::G2Projective>(scalar)
        }
    };

    let transformed_vec: Vec<jbyte> = fe_bytes.iter().map(|&x| x as jbyte).collect();

    let random_scalar_jbytes: [jbyte; FIELD_ELEMENT_SIZE] =
        match transformed_vec.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return -1003,
        };

    match env.set_byte_array_region(output, 0, &random_scalar_jbytes) {
        Ok(_) => 0,
        Err(_) => -1004,
    }
}

/// Creates a one value scalar
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A jint indicating the elliptic curve group to use.
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// *   0    Success
/// * -1000  Jni Error: Could not convert group_assignment array to an int representation
/// * -1003  Rust error: Could not convert output vector to a jByte array of size FIELD_ELEMENT_SIZE
/// * -1004  Jni Error: Could not set the scalar in the output byte array
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsOne(
    env: JNIEnv,
    _instance: JObject,
    group_assignment: jint,
    output: JByteArray,
) -> jint {
    let group_byte = match u8::try_from(group_assignment) {
        Ok(val) => val,
        Err(_) => return -1000,
    };

    let fe_bytes = match group_byte {
        0 => {
            let scalar = scalars_one::<ark_bn254::G2Projective>();
            scalars_to_bytes::<ark_bn254::G2Projective>(scalar)
        }
        _ => {
            let scalar = scalars_one::<ark_bn254::G1Projective>();
            scalars_to_bytes::<ark_bn254::G2Projective>(scalar)
        }
    };

    let transformed_vec: Vec<jbyte> = fe_bytes.iter().map(|&x| x as jbyte).collect();

    let random_scalar_jbytes: [jbyte; FIELD_ELEMENT_SIZE] =
        match transformed_vec.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => return -1003,
        };

    match env.set_byte_array_region(output, 0, &random_scalar_jbytes) {
        Ok(_) => 0,
        Err(_) => -1004,
    }
}

/// returns if the two representations of a field element are the same
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A jint indicating the elliptic curve group to use.
/// * `value`   the byte that represents the scalar 1
/// * `value2`  the byte that represents the scalar 2
/// # Returns
/// *   0    False
/// *   1    True
/// * -1000  Jni Error: group_assignment Could not be converted to an int representation
/// * -1001  Jni Error: value Could not convert input_seed array to vector
/// * -1002  Rust error: value Could not convert vector to an unsigned byte array of size SEED_SIZE
/// * -1005  Rust error: value2 Could not convert vector to an unsigned byte array of size SEED_SIZE
/// * -1006  Rust error: value2 Could not convert vector to an unsigned byte array of size SEED_SIZE
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_fieldElementsEquals(
    env: JNIEnv,
    _instance: JObject,
    group_assignment: jint,
    value: JByteArray,
    value2: JByteArray,
) -> jint {
    let group_byte = match u8::try_from(group_assignment) {
        Ok(val) => val,
        Err(_) => return -1000,
    };

    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return -1001,
    };

    let input_array: [u8; FIELD_ELEMENT_SIZE] = match input_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return -1002,
    };

    let input_bytes2 = match env.convert_byte_array(&value2) {
        Ok(val) => val,
        Err(_) => return -1005,
    };

    let input_array2: [u8; FIELD_ELEMENT_SIZE] = match input_bytes2.try_into() {
        Ok(val) => val,
        Err(_) => return -1006,
    };

    (match group_byte {
        0 => {
            let scalar = scalars_from_bytes::<ark_bn254::G2Projective>(&input_array);
            let scalar2 = scalars_from_bytes::<ark_bn254::G2Projective>(&input_array2);
            scalar == scalar2
        }
        _ => {
            let scalar = scalars_from_bytes::<ark_bn254::G1Projective>(&input_array);
            let scalar2 = scalars_from_bytes::<ark_bn254::G1Projective>(&input_array2);
            scalar == scalar2
        }
    }) as jint
}
