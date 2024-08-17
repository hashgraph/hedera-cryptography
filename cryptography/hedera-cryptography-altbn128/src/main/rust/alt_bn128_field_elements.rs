use std::mem;
use ark_bn254::Fq;
use ark_ec::{CurveConfig, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use jni::JNIEnv;
use jni::objects::{JByteArray, JObject, JObjectArray};
use jni::sys::{jbyte, jbyteArray, jint};
use rand::Rng;
use rand::rngs::OsRng;
use rand_chacha::ChaChaRng;
use rand_chacha::rand_core::SeedableRng;
use crate::pairings_api::*;

/// Serializes a scalar field element into a byte vector.
///
/// # Arguments
/// * `element` - A reference to the scalar field element to be serialized.
/// * `serialized` - A mutable byte vector to store the serialized data.
///
/// # Returns
/// The byte vector containing the serialized scalar field element.
fn serialize_field_element<G: CurveGroup>(element: &<<G as CurveGroup>::Config as CurveConfig>::ScalarField, mut serialized: Vec<u8>) -> Vec<u8> {
    element.serialize_uncompressed(&mut serialized).unwrap();
    serialized
}


/// Serializes an affine group element into a byte vector.
///
/// # Arguments
/// * `element` - A reference to the affine group element to be serialized.
/// * `serialized` - A mutable byte vector to store the serialized data.
///
/// # Returns
/// The byte vector containing the serialized affine group element.
fn serialize_group_element<G: CurveGroup>(element: &G::Affine, mut serialized: Vec<u8>) -> Vec<u8> {
    element.serialize_uncompressed(&mut serialized).unwrap();
    serialized
}

/// Deserializes an u8 slice into a scalar field element.
///
/// # Arguments
/// * `serialized_sk` - An u8 slice containing the serialized scalar field element.
///
/// # Returns
/// A deserialized scalar field element.
fn deserialize_field_element<G: CurveGroup>(
    serialized_sk: &[u8],
) -> <<G as CurveGroup>::Config as CurveConfig>::ScalarField {

    // Deserialize the serialized_sk into a scalar field element
    let sk = <<G as CurveGroup>::Config as CurveConfig>::ScalarField::deserialize_uncompressed(&serialized_sk[..])
        .map_err(|_| "Deserialization failed").unwrap();
    sk
}

/// Generates a key pair (private key and public key) for a given elliptic curve ark_bn254 group.
///The private key is random scalar 𝑘 from the Field of the curve.
///The public key is calculated as 𝑘 × 𝐺 where
/// * k is the private key and
/// * 𝐺 :  is a predefined generator point on the curve.
/// # Arguments
/// * `rng` - A mutable reference to a random number generator.
///
/// # Returns
/// A tuple containing the private key (scalar field element) and the public key (affine group element).
fn key_pair<G: CurveGroup, R: Rng>(rng: &mut R) -> (<<G as CurveGroup>::Config as CurveConfig>::ScalarField, <G as CurveGroup>::Affine) {
    let sk = G::ScalarField::rand(rng);
    let generator = G::generator();
    let pk = generator.mul(&sk);
    (sk, pk.into_affine())
}

/// Computes the public key from a given private key (scalar field element).
///The public key is calculated as 𝑘 × 𝐺 where
/// * k is the private key and
/// * 𝐺 :  is a predefined generator point on the curve.
/// # Arguments
/// * `sk` - The private key (scalar field element).
///
/// # Returns
/// The public key (affine group element).
fn pub_key<G: CurveGroup>( sk: <<G as CurveGroup>::Config as CurveConfig>::ScalarField) ->  <G as CurveGroup>::Affine{
    let generator = G::generator();
    let pk = generator.mul(&sk);
     pk.into_affine()
}

/// Generates a key pair (private key and public key) and serializes them into byte vectors.
///
/// # Arguments
/// * `rng` - A mutable reference to a random number generator.
///
/// # Returns
/// A tuple containing the serialized private key and serialized public key.
fn gen_serialized_pair<G: CurveGroup, R: Rng>(rng: &mut R ) -> (Vec<u8>, Vec<u8>){
    let(sk, pk) = key_pair::<G, R>(rng);
    let sk_bytes =   Vec::new();
    let serialized_sk = serialize_field_element::<G>(&sk, sk_bytes);
    let pk_bytes =  Vec::new();
    let serialized_pk = serialize_group_element::<G>(&pk, pk_bytes);
    (serialized_sk,  serialized_pk)
}

/// Computes the public key from a given private key (scalar field element) and serializes them into byte vectors.
///
/// # Arguments
/// * `sk` - The private key (scalar field element).
///
/// # Returns
/// The serialized public key.
fn gen_serialized_pub_key<G: CurveGroup>( sk: <<G as CurveGroup>::Config as CurveConfig>::ScalarField) ->  Vec<u8>{
    let pk_bytes =  Vec::new();
    let pk: <G as CurveGroup>::Affine = pub_key::<G>(sk);
    serialize_group_element::<G>(&pk, pk_bytes)
}

/// the id this node will use for identifying shares
pub type FieldElement<G> = <<G as CurveGroup>::Config as CurveConfig>::ScalarField;


/// JNI function to generate a key pair (private key and public key) and return them in a Java byte array
/// of two elements where index 0 represents the private key, and index 1 the public key.
///
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A jint indicating the elliptic curve group to use.
///
/// # Returns
///  A Java byte[][] array to store the resulting private key and public key.
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_jni_AltBn128FieldElements_generateKeyPair<'local>(
    mut env:  JNIEnv<'local>,
    _instance: JObject,
    group_assignment: jint,
) -> JObjectArray<'local> {
    let mut rng = OsRng;
    let group_byte = u8::try_from(group_assignment).expect("Invalid group assignment");
    let (serialized_sk, serialized_pk) = match group_byte {
        0 => gen_serialized_pair::<ark_bn254::G2Projective, OsRng>(&mut rng),
        _ => gen_serialized_pair::<ark_bn254::G1Projective, OsRng>(&mut rng),
    };

    let sk_len = serialized_sk.len() as i32;
    let pk_len = serialized_pk.len() as i32;

    let jbyte_array_sk = env.new_byte_array(sk_len).expect("Failed to create new byte array for private key");
    let jbyte_array_pk = env.new_byte_array(pk_len).expect("Failed to create new byte array for public key");

    // Convert Vec<u8> to &[u8]
    let sk_slice: &[u8] = &serialized_sk;
    let pk_slice: &[u8] = &serialized_pk;

    // Convert &[u8] to &[jbyte]
    let sk_jbytes: &[jbyte] = unsafe { std::mem::transmute(sk_slice) };
    let pk_jbytes: &[jbyte] = unsafe { std::mem::transmute(pk_slice) };

    env.set_byte_array_region(&jbyte_array_sk, 0, sk_jbytes).expect("Failed to set byte array region for private key");
    env.set_byte_array_region(&jbyte_array_pk, 0, pk_jbytes).expect("Failed to set byte array region for public key");

    let class = env.get_object_class(&jbyte_array_sk).expect("Failed to get the class");
    let output:JObjectArray<'local> = env.new_object_array(2, class,JObject::null() ).expect("Failed to create output array for key pair") ;
    env.set_object_array_element(&output, 0, &jbyte_array_sk).expect("Failed to set object array element for private key");
    env.set_object_array_element(&output, 1, &jbyte_array_pk).expect("Failed to set object array element for public key");
    output
}

/// JNI function to create a new random scalar from a seed value
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input_seed` the byte seed to be used to create the new scalar
/// * `output`  the byte array that will be filled with the new scalar
/// # Returns
/// a non-zero error code if there was an error, otherwise 0
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_jni_AltBn128FieldElements_fieldElementsFromRandomSeed(
    mut env:  JNIEnv,
    _instance: JObject,
    input_seed: JByteArray,
    output: JByteArray,
) -> jint {

    let input_seed_bytes = match env.convert_byte_array(&input_seed) {
        Ok(val) => val,
        Err(err) => return 1000
    };

    let seed_array: [u8; 32] = match input_seed_bytes.try_into() {
        Ok(val) => val,
        Err(err) => return 1001
    };

    let random_scalar_bytes: [u8; 32] = field_elements_from_random::<ark_bn254::Fr>(seed_array).to_bytes();

    let random_scalar_jbytes: &[jbyte; 32] = unsafe { mem::transmute(&random_scalar_bytes) };

    return match env.set_byte_array_region(output, 0, random_scalar_jbytes) {
        Ok(_) => 0,
        Err(err) => 1002
    };

}

/// JNI function to create a new scalar from a long
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input_long`  the long to be used to create the new scalar
/// * `output`   the byte array that will be filled with the new scalar
/// # Returns
/// * non-zero error code if there was an error, otherwise 0
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_jni_AltBn128FieldElements_fieldElementsFromLong(
    mut env:  JNIEnv,
    _instance: JObject,
    input: jint,
    output: JObjectArray,
) -> jint {
    0
}

/// JNI function to determine if the input representation is a valid FieldElement
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `input`  the that represents the scalar
/// # Returns
/// * 0 if is valid, -1 if not valid, otherwise non-zero error code if there was an error
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_jni_AltBn128FieldElements_fieldElementsIsValid(
    mut env:  JNIEnv,
    _instance: JObject,
    input: JObjectArray
) -> jint {
    0
}

/**
 * Creates a new zero value scalar
 *
 * @param output the byte array that will be filled with the new scalar
 * @return a non-zero error code if there was an error, otherwise 0
 */
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_jni_AltBn128FieldElements_fieldElementsZero(
    mut env:  JNIEnv,
    _instance: JObject,
    output: JObjectArray
) -> jint {
 0
}

/// JNI function to create a new one value scalar.
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `output` the byte array that will be filled with the new scalar
/// # Returns
/// * a non-zero error code if there was an error, otherwise 0
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_jni_AltBn128FieldElements_fieldElementsOne(
    mut env:  JNIEnv,
    _instance: JObject,
    output: JObjectArray
) -> jint {
 0
}
