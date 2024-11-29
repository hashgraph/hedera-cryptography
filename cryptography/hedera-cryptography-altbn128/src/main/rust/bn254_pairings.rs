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

use crate::jni_helpers;
use crate::jni_helpers::{G1, G2};
use crate::pairings_utils::pairings_is_equal;
use ark_ec::CurveGroup;
use jni::objects::{JByteArray, JObject};
use jni::sys::jint;
use jni::JNIEnv;

/// returns if the paring between the first two points is equals to the pairings of the second group of two points
/// # Arguments
/// * `env` _ The JNI environment.
/// * `_instance` _ The Java instance calling this function.
/// * `group_id`  in which group to perform the operation
/// * `value1`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element of group 1
/// * `value2`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element of group 2
/// * `value3`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element of group 1
/// * `value4`   the byte that of size GROUP2_ELEMENT_SIZE represents the group element of group 2
/// # Returns
/// *   0    False
/// *   1    True
/// * A less than 0 error code in case of error

#[no_mangle]
pub extern "system" fn Java_com_hedera_cryptography_altbn128_adapter_jni_ArkBn254Adapter_pairingsEquals(
    env: JNIEnv,
    _instance: JObject,
    value: JByteArray,
    value2: JByteArray,
    value3: JByteArray,
    value4: JByteArray,
) -> jint {
    let p1: G1 = match jni_helpers::to_point::<G1>(&env, &value) {
        Ok(val) => val,
        Err(err) => return err,
    };
    let p2: G2 = match jni_helpers::to_point::<G2>(&env, &value2) {
        Ok(val) => val,
        Err(err) => return err,
    };
    let p3: G1 = match jni_helpers::to_point::<G1>(&env, &value3) {
        Ok(val) => val,
        Err(err) => return err,
    };
    let p4: G2 = match jni_helpers::to_point::<G2>(&env, &value4) {
        Ok(val) => val,
        Err(err) => return err,
    };
    pairings_is_equal(
        p1.into_affine().into(),
        p2.into_affine().into(),
        p3.into_affine().into(),
        p4.into_affine().into(),
    ) as jint
}
