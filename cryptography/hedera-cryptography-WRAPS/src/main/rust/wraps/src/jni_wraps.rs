use jni::sys::{jbyteArray, jboolean, jobject, jsize, jint, JNI_VERSION_1_2};
use jni::{JNIEnv, JavaVM};
use jni::objects::{JByteArray, JObject, JObjectArray, JValue};
use std::env;
use ark_serialize::CanonicalDeserialize;

use crate::{jni_util, utils, WRAPS, SigningProtocolPhase, ENTROPY_SIZE, SchnorrPrivKey, SchnorrPubKey, SigningProtocolMessage, SigningProtocolObject};

const SECRET_KEY_LENGTH: usize = 32;

/// The default level of parallelism if the TSS_LIB_NUM_OF_CORES env var is missing or invalid.
const DEFAULT_NUM_OF_CORES: usize = 1;

/// JNI_OnLoad gets called only once when the library is first loaded into the process
#[no_mangle]
pub extern "system" fn JNI_OnLoad(
    _vm: JavaVM,
    _reserved: *const u8,
) -> jint {
    // Limit the concurrency per the configuration. This can only be done once, and must be done
    // before the SNARK library has had a chance to do this. If we try to call `build_global()` again,
    // whether with the same num_of_cores or a different one, it will return an Err Result
    // and not have any effect.
    // So we do this here in this JNI_OnLoad function first thing when this library loads.
    let num_of_cores = match env::var("TSS_LIB_NUM_OF_CORES") {
        Ok(val) => val.parse::<usize>().unwrap_or(DEFAULT_NUM_OF_CORES),
        Err(_) => DEFAULT_NUM_OF_CORES
    };

    // NOTE: as of 10/14/2025, we actually don't use parallelism in WRAPS 2.0, and so we don't
    // really use rayon just yet. So today the below operation is effectively a no-op as this
    // doesn't affect anything in the WRAPS today.
    // However, we'll be adding support for parallelism in the near future to enable faster
    // computations. So we take a dependency on rayon and do this preemptively:
    let _ = rayon::ThreadPoolBuilder::new().num_threads(num_of_cores).build_global();

    JNI_VERSION_1_2
}

/// JNI for WRAPSLibraryBridge.generateSchnorrKeysImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_generateSchnorrKeysImpl(
    mut env: JNIEnv,
    _instance: JObject,
    random_jarray: JByteArray,
) -> jobject {
    let random_arr = match jni_util::build_entropy_array(&env, &random_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let (private_key, public_key) = match WRAPS::keygen(random_arr) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let serialized_private_key = jni_util::u8_vec_to_jbyte_array(&env, &utils::serialize(&private_key));
    let serialized_public_key = jni_util::u8_vec_to_jbyte_array(&env, &utils::serialize(&public_key));

    let keys_clz = match env.find_class("com/hedera/cryptography/wraps/SchnorrKeys") {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let keys_obj = match env.new_object(keys_clz, "([B[B)V", &[JValue::from(&JObject::from_raw(serialized_private_key)), JValue::from(&JObject::from_raw(serialized_public_key))]) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    keys_obj.into_raw()
}

/// JNI for WRAPSLibraryBridge.runSigningProtocolPhaseImpl
#[no_mangle]
pub unsafe extern "system" fn Java_com_hedera_cryptography_wraps_WRAPSLibraryBridge_runSigningProtocolPhaseImpl(
    mut env: JNIEnv,
    _instance: JObject,
    phase_ordinal: jint,
    random_jarray: JByteArray,
    message_jarray: JByteArray,
    schnorr_private_key_jarray: JByteArray,
    schnorr_public_keys_jarray: JObjectArray,
    round1messages_jarray: JObjectArray,
    round2messages_jarray: JObjectArray,
    round3messages_jarray: JObjectArray,
) -> jbyteArray {
    let phase = match phase_ordinal {
        0 => SigningProtocolPhase::R1,
        1 => SigningProtocolPhase::R2,
        2 => SigningProtocolPhase::R3,
        3 => SigningProtocolPhase::Aggregate,
        _ => return std::ptr::null_mut()
    };

    let random_arr: Option<[u8; ENTROPY_SIZE]> = if random_jarray.is_null() { None } else {
        match jni_util::build_entropy_array(&env, &random_jarray) {
            Ok(val) => Some(val),
            Err(_) => return std::ptr::null_mut()
        }
    };

    let message = match env.convert_byte_array(&message_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let signing_key: Option<SchnorrPrivKey> = if schnorr_private_key_jarray.is_null() { None } else {
        let signing_key_vec: Vec<u8> = match env.convert_byte_array(&schnorr_private_key_jarray) {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        let signing_key_arr: &[u8; SECRET_KEY_LENGTH] = match signing_key_vec.as_slice().try_into() {
            Ok(val) => val,
            Err(_) => return std::ptr::null_mut()
        };
        match SchnorrPrivKey::deserialize_uncompressed(&signing_key_arr[..]) {
            Ok(val) => Some(val),
            Err(_) => return std::ptr::null_mut()
        }
    };

    let public_keys: Vec<SchnorrPubKey> = match jni_util::build_vector(&mut env, &schnorr_public_keys_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let round1messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round1messages_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let round2messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round2messages_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };
    let round3messages: Vec<SigningProtocolMessage> = match jni_util::build_vector(&mut env, &round3messages_jarray) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let obj: SigningProtocolObject = match WRAPS::signing_protocol(phase, random_arr, message, signing_key.as_ref(), &public_keys, &round1messages, &round2messages, &round3messages) {
        Ok(val) => val,
        Err(_) => return std::ptr::null_mut()
    };

    let serialized_obj = match obj {
        SigningProtocolObject::ProtocolMessage(msg_encoded) => utils::serialize(&msg_encoded),
        SigningProtocolObject::ProtocolOutput(signature) => utils::serialize(&signature)
    };

    jni_util::u8_vec_to_jbyte_array(&env, &serialized_obj)
}
