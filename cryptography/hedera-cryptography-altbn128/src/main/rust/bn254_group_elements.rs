use crate::group_element_utils::*;
use crate::scalars_utils::scalars_from_bytes;
use jni::objects::{JByteArray, JObject, JObjectArray};
use jni::sys::{jbyte, jint, jsize};
use jni::JNIEnv;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

const GROUP2_SEED_SIZE: usize = 32;
const GROUP2_ELEMENT_SIZE: usize = 128;
type G = ark_bn254::G2Projective;

/// The following is a list of all possible return codes by the JNI functions in this file
/// * 0     False
/// * 1     True
/// * 0     Success
const SUCCESS: i32 = 0;
/// * -4    Business Error: Point is not in the curve
const BUSINESS_ERROR_POINT_NOT_IN_CURVE: i32 = -4;
/// * -2001  Jni Error: Could not convert argument array to vector
const JNI_ERROR_ARG_TO_VEC: i32 = -2001;
/// * -2002  Rust error: Could not convert argument vector to an unsigned byte array
const RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE: i32 = -2002;
/// * -2003  Ark Error: Result cannot be serialized
const ARK_ERROR_RESULT_SERIALIZATION: i32 = -2003;
/// * -2004  Rust error: Could not convert the result vector to a jByte array
const RUST_ERROR_COULD_NOT_TRANSFORM_RESULT_DATA_TYPE: i32 = -2004;
/// * -2005  Jni Error: Could not set the result in the output byte array
const JNI_ERROR_COULD_SET_RESULT_DATA_IN_ARRAY: i32 = -2005;
/// * -2006  Jni Error: Could not convert argument2 array to vector
const JNI_ERROR_ARG2_TO_VEC: i32 = -2006;
/// * -2007  Ark Error: argument cannot be deserialized
const ARK_ERROR_ARGUMENT_SERIALIZATION: i32 = -2007;
/// * -2008  Jni Error: Could not total length of the argument matrix
const JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE: i32 = -2008;
/// * -2009  Jni Error: Could not get one of the results in array argument
const JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE: i32 = -2009;
/// * -2010  Jni Error: Could not transform one of the results elements data type
const JNI_ERROR_COULD_NOT_TRANSFORM_RESULT_ELEMENT: i32 = -2010;
/// * -2011  Jni Error: Could not set one of the results elements int the response matrix
const JNI_ERROR_COULD_SET_RESULT_DATA_IN_MATRIX: i32 = -2011;

/// Utility function to write the serialized representation of a point in an existing JByteArray
fn write_return_point(env: JNIEnv, point: &G, output: JByteArray) -> Result<jint, jint> {
    let ge_bytes = match group_elements_serialize::<G>(&point) {
        Ok(val) => val,
        Err(_) => return Err(ARK_ERROR_RESULT_SERIALIZATION),
    };

    let transformed_vec: Vec<jbyte> = ge_bytes.iter().map(|&x| x as jbyte).collect();
    let ge_jbytes: [jbyte; GROUP2_ELEMENT_SIZE] = match transformed_vec.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(RUST_ERROR_COULD_NOT_TRANSFORM_RESULT_DATA_TYPE),
    };

    match env.set_byte_array_region(output, 0, &ge_jbytes) {
        Ok(_) => Ok(SUCCESS),
        Err(_) => Err(JNI_ERROR_COULD_SET_RESULT_DATA_IN_ARRAY),
    }
}

/// Utility function read a curve point form a JbyteArray, the point is validated, so this function must be used with trusted source of information.
fn to_point(env: &JNIEnv, value: &JByteArray) -> Result<G, jint> {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };

    let point1 = match group_elements_deserialize::<G>(&input_bytes) {
        Ok(val) => val,
        Err(_) => return Err(ARK_ERROR_ARGUMENT_SERIALIZATION),
    };
    Ok(point1)
}

/// JNI function to create a new random group element from a seed value
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `input_seed`   the byte array of size GROUP2_ELEMENT_SIZE represents the group element
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2FromSeed(
    env: JNIEnv,
    _instance: JObject,
    input_seed: JByteArray,
    output: JByteArray,
) -> jint {
    let input_seed_bytes = match env.convert_byte_array(&input_seed) {
        Ok(val) => val,
        Err(_) => return JNI_ERROR_ARG_TO_VEC,
    };

    let seed_array: [u8; GROUP2_SEED_SIZE] = match input_seed_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE,
    };

    let mut rng = ChaCha8Rng::from_seed(seed_array);
    let point = group_elements_from_random::<G, ChaCha8Rng>(&mut rng);

    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// JNI function that determines if a byte array representation of a group element is valid
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `value`   the byte that of size GROUP2_ELEMENT_AFFINE_SIZE represents the group element
/// # Returns
/// *   0    Success
/// *  BUSINESS_ERROR_POINT_NOT_IN_CURVE   Business Error: Point is not in the curve
/// *  A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2Bytes(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
) -> jint {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return JNI_ERROR_ARG_TO_VEC,
    };

    let input_array: [u8; GROUP2_ELEMENT_SIZE] = match input_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE,
    };

    let point = match group_elements_deserialize_and_validate::<G>(&input_array) {
        Ok(val) => val,
        Err(_) => return BUSINESS_ERROR_POINT_NOT_IN_CURVE,
    };
    if !point.is_on_curve() {
        return BUSINESS_ERROR_POINT_NOT_IN_CURVE;
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        BUSINESS_ERROR_POINT_NOT_IN_CURVE
    } else {
        SUCCESS
    }
}

/// Returns the zero group element
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2Zero(
    env: JNIEnv,
    _instance: JObject,
    output: JByteArray,
) -> jint {
    let point = group_elements_zero::<G>();
    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// Returns the Generator group element
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2Generator(
    env: JNIEnv,
    _instance: JObject,
    output: JByteArray,
) -> jint {
    let point = group_elements_generator::<G>();
    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// returns if the two representations of a group element are the same
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `value`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element
/// * `value2`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element 2
/// # Returns
/// *   0    False
/// *   1    True
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2Equals(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
) -> jint {
    let point1 = match to_point(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point2 = match to_point(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    (point1 == point2) as jint
}

/// returns the size in bytes of a group element object representation
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// # Returns
/// *   the value of GROUP2_ELEMENT_SIZE constant
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2Size(
    _env: JNIEnv,
    _instance: JObject,
) -> jint {
    GROUP2_ELEMENT_SIZE as jint
}

/// returns the size in bytes of the random seed to use
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// # Returns
/// *   the value of GROUP2_SEED_SIZE constant
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2RandomSeedSize(
    _env: JNIEnv,
    _instance: JObject,
) -> jint {
    GROUP2_SEED_SIZE as jint
}

/// Panics
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_panicTest(
    _env: JNIEnv,
    _instance: JObject,
) -> jint {
    panic!("Something went wrong!");
}

/// returns the sum of two representations of a group elements
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `value`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element
/// * `value2`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element 2
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns

/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2Add(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
    output: JByteArray,
) -> jint {
    let point1 = match to_point(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point2 = match to_point(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point = group_elements_add(point1, point2);
    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// returns the multiplication of a group elements and a scalar
/// in this notation this is the power operation
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `value`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element
/// * `value2`  the byte that represents the scalar
/// * `output`   the byte array of size GROUP2_ELEMENT_SIZE that will be filled with the resulting group element
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2ScalarMul(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
    output: JByteArray,
) -> jint {
    let point1 = match to_point(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let input_bytes2 = match env.convert_byte_array(&value2) {
        Ok(val) => val,
        Err(_) => return JNI_ERROR_ARG2_TO_VEC,
    };

    let value = scalars_from_bytes(&input_bytes2);

    let point = group_elements_scalar_multiply(point1, value);
    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// JNI function to return the batch addition of N group elements
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `values`   the byte matrix that represents the collection of group elements
/// * `output`   the byte array that will be filled with the new point representing the result of the operation
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2batchAdd(
    mut env: JNIEnv,
    _instance: JObject,
    values: JObjectArray,
    output: JByteArray,
) -> jint {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE,
    };
    let mut points = Vec::new();
    for i in 0..n {
        let element = match env.get_object_array_element(&values, i as jsize) {
            Ok(val) => val,
            Err(_) => return JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE,
        };

        let element_byte_array: JByteArray = unsafe { JByteArray::from_raw(*element) };
        let point1 = match to_point(&env, &element_byte_array) {
            Ok(value) => value,
            Err(value) => return value,
        };
        points.push(point1);
    }

    let point = group_elements_total_sum(points);

    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// JNI function to return the batch multiplication of the group generator with N scalars
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `values`   the byte matrix that represents the collection of group elements
/// * `output`   the byte array that will be filled with the new point representing the result of the operation
/// # Returns
/// *   0    Success
/// * A less than 0 error code in case of error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_g2batchScalarMultiplication(
    mut env: JNIEnv,
    _instance: JObject,
    values: JObjectArray,
    outputs: JObjectArray,
) -> jint {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE,
    };

    let mut scalars = Vec::new();
    for i in 0..n {
        let element = match env.get_object_array_element(&values, i as jsize) {
            Ok(val) => val,
            Err(_) => return JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE,
        };

        let element_byte_array: JByteArray = unsafe { JByteArray::from_raw(*element) };

        let input_bytes = match env.convert_byte_array(&element_byte_array) {
            Ok(val) => val,
            Err(_) => return JNI_ERROR_ARG_TO_VEC,
        };

        let scalar = scalars_from_bytes(&input_bytes);
        scalars.push(scalar);
    }

    let results = group_elements_batch_multiply::<G>(scalars);

    for (i, entry) in results.iter().enumerate() {
        let ge_bytes = match group_elements_serialize::<G>(&entry) {
            Ok(val) => val,
            Err(_) => return ARK_ERROR_RESULT_SERIALIZATION,
        };

        let element = match env.byte_array_from_slice(&ge_bytes) {
            Ok(val) => val,
            Err(_) => return JNI_ERROR_COULD_NOT_TRANSFORM_RESULT_ELEMENT,
        };

        match env.set_object_array_element(&outputs, i as jsize, element) {
            Ok(_) => SUCCESS,
            Err(_) => return JNI_ERROR_COULD_SET_RESULT_DATA_IN_MATRIX,
        };
    }
    SUCCESS
}
