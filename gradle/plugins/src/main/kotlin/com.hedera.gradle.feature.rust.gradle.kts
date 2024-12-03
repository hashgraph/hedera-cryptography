/*
 * Copyright (C) 2022-2024 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.hedera.gradle.extensions.CargoExtension
import com.hedera.gradle.extensions.CargoToolchain
import com.hedera.gradle.extensions.CargoToolchain.aarch64Linux
import com.hedera.gradle.extensions.CargoToolchain.x86Linux
import com.hedera.gradle.extensions.CargoToolchain.x86Windows
import org.apache.tools.ant.taskdefs.condition.Os

plugins { id("java") }

val cargo = project.extensions.create<CargoExtension>("cargo")

// TODO: https://github.com/hashgraph/hedera-cryptography/issues/94
// Remove the conditional compilation once the ticket is addressed.
// It seems to be a problem with llc liker when zig is executed in the github runners
if (Os.isFamily(Os.FAMILY_MAC)) {
    cargo.targets(*CargoToolchain.values())
} else {
    cargo.targets(aarch64Linux, x86Linux, x86Windows)
}
