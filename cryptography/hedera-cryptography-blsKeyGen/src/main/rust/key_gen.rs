use ark_ec::{CurveConfig, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use base64::Engine;
use base64::engine::general_purpose;
use jni::JNIEnv;
use jni::objects::{JClass, JObjectArray};
use jni::sys::{jbyte, jint};
use rand::Rng;
use rand::rngs::OsRng;


pub fn keygen<G: CurveGroup, R: Rng>(rng: &mut R) -> (<<G as CurveGroup>::Config as CurveConfig>::ScalarField, <G as CurveGroup>::Affine) {
    let sk = G::ScalarField::rand(rng);
    let generator = G::generator();
    let pk = generator.mul(&sk);
    (sk, pk.into_affine())
}

pub fn serialize_field_element<G: CurveGroup>(element: &<<G as CurveGroup>::Config as CurveConfig>::ScalarField, mut serialized: Vec<u8>) -> Vec<u8> {
    element.serialize_uncompressed(&mut serialized).unwrap();
    serialized
}

pub fn serialize_group_element<G: CurveGroup>(element: &G::Affine, mut serialized: Vec<u8>) -> Vec<u8> {
    element.serialize_uncompressed(&mut serialized).unwrap();
    serialized
}

pub fn gen_pair<G: CurveGroup, R: Rng>(rng: &mut R, group_byte: u8 )  -> (String, String){
    let(sk, pk) = keygen::<G, R>(rng);
    let mut sk_bytes =   Vec::new();
    sk_bytes.push(group_byte);
    let serialized_sk = serialize_field_element::<G>(&sk, sk_bytes);
    let mut pk_bytes =  Vec::new();
    pk_bytes.push(group_byte);
    let serialized_pk = serialize_group_element::<G>(&pk, pk_bytes);
    ( general_purpose::STANDARD.encode(serialized_sk),  general_purpose::STANDARD.encode(serialized_pk))
}

#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_blsKeyGen_BlsKeyGen_generateKeyPair(
    env: JNIEnv,
    _class: JClass,
    signature_schema: jbyte,
    output: JObjectArray,
) ->jint{
    let mut rng = OsRng;
    let group_byte = u8::try_from(signature_schema).expect("Invalid group ID");
    let (serialized_sk, serialized_pk) =  match group_byte {
        1 => {
            gen_pair::<ark_bn254::G2Projective, OsRng>(& mut rng, group_byte)
        }
        _ => {
            gen_pair::<ark_bn254::G1Projective, OsRng>(& mut rng, group_byte)
        }

    };

    let jstr_sk = match env.new_string(&serialized_sk){
        Ok(val) => val,
        Err(_err) => return -1
    };

    let jstr_pk = match env.new_string(&serialized_pk){
        Ok(val) => val,
        Err(_err) => return -1
    };

    match env.set_object_array_element(&output, 0, jstr_sk){
        Ok(val) => val,
        Err(_err) => return -1
    };

    match env.set_object_array_element(&output, 1, jstr_pk){
        Ok(val) => val,
        Err(_err) => return -1
    };

    0
}



