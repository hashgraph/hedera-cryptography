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
