use ark_ec::{CurveConfig, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use jni::JNIEnv;
use jni::objects::{JByteArray, JObject, JObjectArray};
use jni::sys::{jbyte, jint};
use rand::Rng;
use rand::rngs::OsRng;


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
///
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
///
/// # Arguments
/// * `sk` - The private key (scalar field element).
///
/// # Returns
/// The public key (affine group element).
fn pub_key<G: CurveGroup>( sk: <<G as CurveGroup>::Config as CurveConfig>::ScalarField,) ->  <G as CurveGroup>::Affine{
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
fn gen_serialized_pub_key<G: CurveGroup>( sk: <<G as CurveGroup>::Config as CurveConfig>::ScalarField,) ->  Vec<u8>{
    let pk_bytes =  Vec::new();
    let pk: <G as CurveGroup>::Affine = pub_key::<G>(sk);
    serialize_group_element::<G>(&pk, pk_bytes)
}


/// JNI function to generate a key pair (private key and public key) and set them in a Java byte array.
///
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A byte indicating the elliptic curve group to use.
/// * `output` - A Java object array to store the resulting private key and public key.
///
/// # Returns
/// An integer status code (0 for success, -1 for failure).
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_blsKeyGen_NativeBlsKeyGen_generateKeyPair(
    env: JNIEnv,
    _instance: JObject,
    group_assignment: jint,
    output: JObjectArray,
) -> jint {
    let mut rng = OsRng;
    let group_byte = u8::try_from(group_assignment).expect("Invalid group assignment");
    let (serialized_sk, serialized_pk) = match group_byte {
        1 => gen_serialized_pair::<ark_bn254::G2Projective, OsRng>(&mut rng),
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

    env.set_object_array_element(&output, 0, &jbyte_array_sk).expect("Failed to set object array element for private key");
    env.set_object_array_element(&output, 1, &jbyte_array_pk).expect("Failed to set object array element for public key");

    0
}


/// JNI function to generate a key pair (private key and public key) and set them in a Java byte array.
///
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// * `group_assignment` - A byte indicating the elliptic curve group to use.
/// * `sk_data` - A Java object array that stores the private key.
///
/// # Returns
/// * A Java object array to of the resulting public key.
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_blsKeyGen_NativeBlsKeyGen_generatePublicKey<'local>(
    env: JNIEnv<'local>,
    _instance: JObject<'local>,
    group_assignment: jint,
    sk_data: JByteArray<'local>,
) -> JByteArray<'local> {

    // Get the length of the byte array
    let array_length = env.get_array_length(
        &sk_data).map_err(|_| "Failed to get array length").unwrap();

    // Create a buffer to hold the byte array contents
    let mut buffer: Vec<jbyte> = vec![0; array_length as usize];

    // Copy the byte array contents into the buffer
    env.get_byte_array_region(sk_data, 0, &mut buffer).map_err(|_| "Failed to get byte array region").unwrap();

    let sk_slice: &[jbyte] = &buffer;
    let sk_jbytes: &[u8] = unsafe { std::mem::transmute(sk_slice) };


    let group_byte = u8::try_from(group_assignment).expect("Invalid group assignment");
    let serialized_pk = match group_byte {
        1 => {
            let sk = deserialize_field_element::<ark_bn254::G2Projective>(sk_jbytes);
            gen_serialized_pub_key::<ark_bn254::G2Projective>(sk)
        },
        _ => {
            let sk= deserialize_field_element::<ark_bn254::G1Projective>(sk_jbytes);
            gen_serialized_pub_key::<ark_bn254::G2Projective>(sk)
        }
    };

    let pk_len = serialized_pk.len() as i32;

    let jbyte_array_pk = env.new_byte_array(pk_len).expect("Failed to create new byte array for public key");

    // Convert Vec<u8> to &[u8]
    let pk_slice: &[u8] = &serialized_pk;

    // Convert &[u8] to &[jbyte]
    let pk_jbytes: &[jbyte] = unsafe { std::mem::transmute(pk_slice) };

    env.set_byte_array_region(&jbyte_array_pk, 0, pk_jbytes).expect("Failed to set byte array region for public key");

    jbyte_array_pk
}