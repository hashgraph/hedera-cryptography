use crate::group_element_utils::{group_elements_add, group_elements_batch_multiply, group_elements_deserialize, group_elements_deserialize_and_validate, group_elements_scalar_multiply, canonical_serialize, group_elements_total_sum};
use crate::scalars_utils::{scalars_curve_from_bytes, scalars_from_bytes, scalars_to_bytes, F};
use ark_bn254::{G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveConfig, CurveGroup};
use ark_serialize::CanonicalSerialize;
use jni::objects::{JByteArray, JObjectArray};
use jni::sys::{jbyte, jint, jsize};
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
/// * -1010  Jni Error: Could not set one of the results elements int the response matrix
const JNI_ERROR_COULD_SET_RESULT_DATA_IN_MATRIX: i32 = -1010;
/// * -1011  Jni Error: Could not set one of the results elements int the response matrix
const JNI_ERROR_COULD_NOT_TRANSFORM_RESULT_ELEMENT: i32 = -1011;
pub type ScalarField<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;
/// * -4    Business Error: Point is not in the curve
const BUSINESS_ERROR_POINT_NOT_IN_CURVE: i32 = -4;

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

/// Utility function to write the serialized representation of a point in an existing JByteArray
pub fn write_return_point<G: CanonicalSerialize>(
    env: JNIEnv,
    point: &G,
    output: JByteArray,
) -> Result<jint, jint> {
    let ge_bytes = match canonical_serialize::<G>(&point) {
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
pub fn to_point<G: CurveGroup>(env: &JNIEnv, value: &JByteArray) -> Result<G, jint> {
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
        let point1 = match to_point::<G>(&env, &element_byte_array) {
            Ok(value) => value,
            Err(value) => return Err(value),
        };
        points.push(point1);
    }
    Ok(points)
}

/// Utility function read a list of scalars form a JObjectArray, if the scalar is bigger than the field a reduction is performed
pub fn to_vec_of_scalars<G: CurveGroup>(
    env: &mut JNIEnv,
    values: JObjectArray,
) -> Result<Vec<ScalarField<G>>, jint> {
    let n = match env.get_array_length(&values) {
        Ok(val) => val as usize,
        Err(_) => return Err(JNI_ERROR_COULD_NOT_GET_ARGUMENT_SIZE),
    };

    let mut scalars = Vec::new();
    for i in 0..n {
        let element = match env.get_object_array_element(&values, i as jsize) {
            Ok(val) => val,
            Err(_) => return Err(JNI_ERROR_CANNOT_RETRIEVE_ARGUMENT_MATRIX_VALUE),
        };

        let element_byte_array: JByteArray = unsafe { JByteArray::from_raw(*element) };

        let input_bytes = match env.convert_byte_array(&element_byte_array) {
            Ok(val) => val,
            Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
        };

        let scalar = scalars_curve_from_bytes::<G>(&input_bytes);
        scalars.push(scalar);
    }
    Ok(scalars)
}

/// Utility function to write a vec of serialized representation of points in a list represented JObjectArray
pub fn write_points_to_jobject_array<G: CurveGroup>(
    env: &mut JNIEnv,
    outputs: &JObjectArray,
    results: Vec<G>,
) -> i32 {
    for (i, entry) in results.iter().enumerate() {
        let ge_bytes = match canonical_serialize::<G>(&entry) {
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

/// Utility function to extract a vec u8 from a JByteArray
pub fn from_jbytearray_to_vec(env: JNIEnv, value: &JByteArray) -> Result<Vec<u8>, jint> {
    let input_bytes = match env.convert_byte_array(&value) {
        Ok(val) => val,
        Err(_) => return Err(JNI_ERROR_ARG_TO_VEC),
    };
    Ok(input_bytes)
}

/// Utility function to validate a g1 point
pub fn validate_g1point(input_bytes: &Vec<u8>) -> i32 {
    let point: G1Affine =
        match group_elements_deserialize_and_validate::<G1Projective>(&input_bytes) {
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

/// Utility function to validate a g2 point
pub fn validate_g2point(input_bytes: &Vec<u8>) -> i32 {
    let point: G2Affine =
        match group_elements_deserialize_and_validate::<G2Projective>(&input_bytes) {
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

/// Utility function to compare two points
pub fn compare_points<G: CurveGroup>(env: &JNIEnv, value: &JByteArray, value2: &JByteArray) -> i32 {
    let point1 = match to_point::<G>(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point2 = match to_point::<G>(&env, &value2) {
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
    let point1 = match to_point::<G>(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point2 = match to_point::<G>(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point = group_elements_add(point1, point2);
    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// Utility function to multiply two points
pub fn multiply_point_and_scalar<G: CurveGroup>(
    env: JNIEnv,
    value: &JByteArray,
    value2: &JByteArray,
    output: JByteArray,
) -> i32 {
    let point1 = match to_point::<G>(&env, &value) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let value = match to_scalar_from_curve::<G>(&env, &value2) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let point = group_elements_scalar_multiply(point1, value);
    write_return_point(env, &point, output).unwrap_or_else(|value| value)
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

    write_return_point(env, &point, output).unwrap_or_else(|value| value)
}

/// Utility function to batch multiply the generator to N scalars
pub fn batch_multiply_points<G: CurveGroup>(
    mut env: JNIEnv,
    values: JObjectArray,
    outputs: JObjectArray,
) -> i32 {
    let scalars = match to_vec_of_scalars::<G>(&mut env, values) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let results = group_elements_batch_multiply::<G>(scalars);

    write_points_to_jobject_array::<G>(&mut env, &outputs, results)
}
