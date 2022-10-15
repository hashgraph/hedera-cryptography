use crate::common::*;
use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::{jbyteArray, jobject, jobjectArray, jint};

#[no_mangle]
pub extern fn test(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray{
    env.byte_array_from_slice(&[0]).unwrap()
    // 1
}