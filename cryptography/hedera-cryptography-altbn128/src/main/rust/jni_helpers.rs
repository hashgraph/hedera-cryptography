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

use crate::group_element_utils::{ canonical_serialize_with_mode, group_elements_add, group_elements_deserialize, group_elements_total_sum,
};
use crate::scalars_utils::{
    scalars_batch_add, scalars_batch_multiply, scalars_curve_from_bytes, scalars_curve_from_i64,
    scalars_curve_group_elements_msm, scalars_curve_group_elements_multiply, scalars_from_bytes,
    scalars_from_i64, scalars_to_bytes, F,
};
use ark_bn254::{G1Projective, G2Projective};
use ark_ec::{CurveConfig, CurveGroup};
use ark_serialize::CanonicalSerialize;
use jni::objects::{JByteArray, JLongArray, JObjectArray};
use jni::sys::{jbyte, jint, jlong, jsize};
use jni::JNIEnv;

pub(crate) type G1 = G1Projective;
pub(crate) type G2 = G2Projective;
/// * 0     False
/// * 1     True
/// * 0     Success
const SUCCESS: i32 = 0;
pub(crate) const SEED_SIZE: usize = 32;
/// * -1001  Jni Error: Could not convert argument array to vector
const JNI_ERROR_ARG_TO_VEC: i32 = -1001;
/// * -1002  Rust error: Could not convert argument vector to an unsigned byte array
const RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE: i32 = -1002;
/// * -1003   Ark Error: Result cannot be serialized
const ARK_ERROR_RESULT_SERIALIZATION: i32 = -1003;
/// * -1004  Jni Error: Could not set the scalar in the output byte array
const JNI_ERROR_COULD_NOT_SET_OUTPUT_BYTE_ARRAY: i32 = -1004;
/// * -1005  Ark Error: argument cannot be deserialized
const ARK_ERROR_ARGUMENT_SERIALIZATION: i32 = -1005;
/// * -1006  Jni Error: Could not set the result in the output byte array
const JNI_ERROR_COULD_SET_RESULT_DATA_IN_ARRAY: i32 = -1006;
/// * -1007  Jni Error: Could not total length of the argument matrix
const JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE: i32 = -1007;
/// * -1009  Jni Error: Could not get one of the results in array argument
const JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE: i32 = -1009;
pub type ScalarField<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;
/// * -4    Business Error: Point is not in the curve
pub(crate) const BUSINESS_ERROR_POINT_NOT_IN_CURVE: i32 = -4;

/// Utility function read a scalar form a JByteArray, if the scalar is bigger than the field a reduction is performed
pub fn to_scalar_from_curve<G: CurveGroup>(
    env: &JNIEnv,
    value: &JByteArray,
) -> Result<ScalarField<G>, i32> {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };

    let scalar = scalars_curve_from_bytes::<G>(&input_bytes);
    Ok(scalar)
}

/// Utility function read a scalar form a JByteArray, if the scalar is bigger than the field a reduction is performed
pub fn to_scalar(env: &JNIEnv, value: &JByteArray) -> Result<F, i32> {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };

    let scalar = scalars_from_bytes(&input_bytes);
    Ok(scalar)
}

/// Utility function to write the serialized representation of a scalar in an existing JByteArray
pub fn write_return_scalar(env: JNIEnv, output: JByteArray, scalar: F) -> Result<jint, jint> {
    let fe_bytes = match scalars_to_bytes(scalar) {
        Ok(val) => val,
        Err(_) => return Err(ARK_ERROR_RESULT_SERIALIZATION),
    };

    let transformed_vec: Vec<jbyte> = fe_bytes.iter().map(|&x| x as jbyte).collect();

    Ok(
        match env.set_byte_array_region(output, 0, &transformed_vec) {
            Ok(_) => SUCCESS,
            Err(_) => JNI_ERROR_COULD_NOT_SET_OUTPUT_BYTE_ARRAY,
        },
    )
}

/// Utility function to extract the random seed from a JByteArray
pub fn extract_random_seed(env: &JNIEnv, input_seed: &JByteArray) -> Result<[u8; 32], jint> {
    let input_seed_bytes = match env.convert_byte_array(&input_seed) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };

    let seed_array: [u8; SEED_SIZE] = match input_seed_bytes.try_into() {
        Ok(val) => val,
        Err(_) => return Err(RUST_ERROR_COULD_NOT_TRANSFORM_ARGUMENT_DATA_TYPE),
    };
    Ok(seed_array)
}

/// Utility function to write the serialized representation in an existing JByteArray
pub fn serialize_to_jbytearray<G: CanonicalSerialize>(
    env: JNIEnv,
    point: &G,
    output: JByteArray,
) -> Result<jint, jint> {
    let ge_bytes = match canonical_serialize_with_mode::<G>(&point,false) {
        Ok(val) => val,
        Err(_) => return Err(ARK_ERROR_RESULT_SERIALIZATION),
    };

    let transformed_vec: Vec<jbyte> = ge_bytes.iter().map(|&x| x as jbyte).collect();

    match env.set_byte_array_region(output, 0, &transformed_vec) {
        Ok(_) => Ok(SUCCESS),
        Err(_) => Err(JNI_ERROR_COULD_SET_RESULT_DATA_IN_ARRAY),
    }
}

/// Utility function to write the serialized representation in an existing JByteArray
pub fn serialize_to_jbytearray_compress<G: CanonicalSerialize>(
    env: JNIEnv,
    point: &G,
    output: JByteArray,
) -> Result<jint, jint> {
    let ge_bytes = match canonical_serialize_with_mode::<G>(&point, true) {
        Ok(val) => val,
        Err(_) => return Err(ARK_ERROR_RESULT_SERIALIZATION),
    };

    let transformed_vec: Vec<jbyte> = ge_bytes.iter().map(|&x| x as jbyte).collect();

    match env.set_byte_array_region(output, 0, &transformed_vec) {
        Ok(_) => Ok(SUCCESS),
        Err(_) => Err(JNI_ERROR_COULD_SET_RESULT_DATA_IN_ARRAY),
    }
}

/// Utility function read a curve point form a JByteArray, the point is not validated, so this function must be used with trusted source of information.
pub fn to_point<G: CurveGroup>(env: &JNIEnv, value: &JByteArray, compress:bool) -> Result<G, jint> {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };

    let point1 = match group_elements_deserialize::<G>(&input_bytes, compress) {
        Ok(val) => val,
        Err(_) => return Err(ARK_ERROR_ARGUMENT_SERIALIZATION),
    };
    Ok(point1)
}

/// Utility function read a list of curve points form a JObjectArray, the point is not validated, so this function must be used with trusted source of information.
pub fn to_vec_of_points<G: CurveGroup>(
    env: &mut JNIEnv,
    values: JObjectArray,
) -> Result<Vec<G>, jint> {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };
    let mut points = Vec::new();
    for i in 0..n {
        let element = match env.get_object_array_element(&values, i as jsize) {
            Ok(val) => val,
            Err(_) => return Err(JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE),
        };

        let element_byte_array: JByteArray = unsafe { JByteArray::from_raw(*element) };
        let point1 = match to_point::<G>(&env, &element_byte_array, false) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };
        points.push(point1);
    }
    Ok(points)
}

/// Utility function read a list of scalars form a JObjectArray.
pub fn from_jobjects_to_vec_of_scalars(
    env: &mut JNIEnv,
    values: JObjectArray,
) -> Result<Vec<F>, jint> {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };
    let mut points = Vec::new();
    for i in 0..n {
        let element = match env.get_object_array_element(&values, i as jsize) {
            Ok(val) => val,
            Err(_) => return Err(JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE),
        };

        let element_byte_array: JByteArray = unsafe { JByteArray::from_raw(*element) };
        let point1 = match to_scalar(&env, &element_byte_array) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };
        points.push(point1);
    }
    Ok(points)
}

/// Utility function read a list of scalars form a JObjectArray.
pub fn from_jobjects_to_vec_of_scalars_curve<G: CurveGroup>(
    env: &mut JNIEnv,
    values: JObjectArray,
) -> Result<Vec<ScalarField<G>>, jint> {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };
    let mut points = Vec::new();
    for i in 0..n {
        let element = match env.get_object_array_element(&values, i as jsize) {
            Ok(val) => val,
            Err(_) => return Err(JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE),
        };

        let element_byte_array: JByteArray = unsafe { JByteArray::from_raw(*element) };
        let point1 = match to_scalar_from_curve::<G>(&env, &element_byte_array) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };
        points.push(point1);
    }
    Ok(points)
}

/// Utility function read a list of scalars form a JObjectArray, if the scalar is bigger than the field a reduction is performed
pub fn from_jlongs_to_vec_of_scalars(env: &mut JNIEnv, values: JLongArray) -> Result<Vec<F>, jint> {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };

    // Prepare a buffer to hold the element
    let mut buffer: Vec<jlong> = vec![0; n];
    match env.get_long_array_region(&values, 0 as jsize, &mut buffer) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };

    let scalars = buffer
        .iter()
        .map(|&x| x as i64)
        .map(|sel| scalars_from_i64(sel))
        .collect();
    Ok(scalars)
}

/// Utility function read a list of scalars form a JObjectArray, if the scalar is bigger than the field a reduction is performed
pub fn from_jlongs_to_vec_of_curve_scalars<G: CurveGroup>(
    env: &mut JNIEnv,
    values: JLongArray,
) -> Result<Vec<ScalarField<G>>, jint> {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };

    // Prepare a buffer to hold the element
    let mut buffer: Vec<jlong> = vec![0; n];
    match env.get_long_array_region(&values, 0 as jsize, &mut buffer) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };

    let scalars = buffer
        .iter()
        .map(|&x| x as i64)
        .map(|sel| scalars_curve_from_i64::<G>(sel))
        .collect();
    Ok(scalars)
}

/// Utility function to extract a vec u8 from a JByteArray
pub fn from_jbytearray_to_vec(env: &JNIEnv, value: &JByteArray) -> Result<Vec<u8>, jint> {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };
    Ok(input_bytes)
}


/// Utility function to compare two points
pub fn compare_points<G: CurveGroup>(env: &JNIEnv, value: &JByteArray, value2: &JByteArray) -> i32 {
    let point1 = match to_point::<G>(&env, &value, false) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point2 = match to_point::<G>(&env, &value2, false) {
        Ok(value) => value,
        Err(value) => return value,
    };

    (point1 == point2) as i32
}

/// Utility function to add two points
pub fn add_points<G: CurveGroup>(
    env: JNIEnv,
    value: &JByteArray,
    value2: &JByteArray,
    output: JByteArray,
) -> i32 {
    let point1 = match to_point::<G>(&env, &value, false) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point2 = match to_point::<G>(&env, &value2, false) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point = group_elements_add(point1, point2);
    serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
}

/// Utility function to multiply a point and a scalar
pub fn multiply_point_and_scalar<G: CurveGroup>(
    env: JNIEnv,
    value: &JByteArray,
    value2: &JByteArray,
    output: JByteArray,
) -> i32 {
    let point1 = match to_point::<G>(&env, &value, false) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let value = match to_scalar_from_curve::<G>(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point = scalars_curve_group_elements_multiply(value, point1);
    serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
}

/// Utility function to produce the total sum of N points
pub fn total_sum_points<G: CurveGroup>(
    mut env: JNIEnv,
    values: JObjectArray,
    output: JByteArray,
) -> i32 {
    let points = match to_vec_of_points::<G>(&mut env, values) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point = group_elements_total_sum(points);

    serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
}

/// Utility function to multiply each scalar[i] with the point in values[i] and return the addition of all the results
pub fn msm_scalars<G: CurveGroup>(
    mut env: JNIEnv,
    scalars: JObjectArray,
    values: JObjectArray,
    outputs: JByteArray,
) -> i32 {
    let scalars = match from_jobjects_to_vec_of_scalars_curve::<G>(&mut env, scalars) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let points = match to_vec_of_points::<G>(&mut env, values) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let result = scalars_curve_group_elements_msm::<G>(scalars, points);

    serialize_to_jbytearray::<G>(env, &result, outputs).unwrap_or_else(|value| value)
}

/// Utility function to multiply each scalar[i] with the point in values[i] and return the addition of all the results
pub fn msm_scalars_longs<G: CurveGroup>(
    mut env: JNIEnv,
    scalars: JLongArray,
    values: JObjectArray,
    outputs: JByteArray,
) -> i32 {
    let scalars_vec = match from_jlongs_to_vec_of_curve_scalars::<G>(&mut env, scalars) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let points = match to_vec_of_points::<G>(&mut env, values) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let result = scalars_curve_group_elements_msm::<G>(scalars_vec, points);

    serialize_to_jbytearray::<G>(env, &result, outputs).unwrap_or_else(|value| value)
}

/// Utility function to multiply each scalar[i] with the point in values[i] and return the addition of all the results
pub fn batch_multiply_scalars(mut env: JNIEnv, scalars: JLongArray, output: JByteArray) -> i32 {
    let scalars = match from_jlongs_to_vec_of_scalars(&mut env, scalars) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let result = scalars_batch_multiply(scalars);

    write_return_scalar(env, output, result).unwrap_or_else(|value| value)
}

/// Utility function to multiply each scalar[i] with the point in values[i] and return the addition of all the results
pub fn batch_add_scalars(mut env: JNIEnv, values: JObjectArray, output: JByteArray) -> i32 {
    let scalars = match from_jobjects_to_vec_of_scalars(&mut env, values) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let result = scalars_batch_add(scalars);

    write_return_scalar(env, output, result).unwrap_or_else(|value| value)
}

/// Utility function to multiply a point and a scalar value
pub fn multiply_point_and_scalar_long<G: CurveGroup>(
    env: JNIEnv,
    value: &JByteArray,
    value2: jlong,
    output: JByteArray,
) -> i32 {
    let point1 = match to_point::<G>(&env, &value, false) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let scalar: i64 = value2 as i64;

    let value: ScalarField<G> = scalars_curve_from_i64::<G>(scalar);

    let point = scalars_curve_group_elements_multiply(value, point1);
    serialize_to_jbytearray(env, &point, output).unwrap_or_else(|value| value)
}
