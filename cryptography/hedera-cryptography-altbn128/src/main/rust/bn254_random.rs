use jni::objects::JObject;
use jni::sys::jint;
use jni::JNIEnv;

/// returns the size in bytes of the random seed to use
/// # Arguments
/// * `env` - The JNI environment.
/// * `_instance` - The Java instance calling this function.
/// # Returns
/// *   the value of SEED_SIZE constant
#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_randomSeedSize(
    _env: JNIEnv,
    _instance: JObject,
) -> jint {
    crate::jni_helpers::SEED_SIZE as jint
}
