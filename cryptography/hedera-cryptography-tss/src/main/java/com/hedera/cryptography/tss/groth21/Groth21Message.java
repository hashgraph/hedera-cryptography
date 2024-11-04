/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
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

package com.hedera.cryptography.tss.groth21;

import com.hedera.cryptography.tss.api.TssMessage;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A message sent as part of either genesis, or rekeying.
 * @implNote the implementation is temporal.
 * @param message byte array representation.
 */
public record Groth21Message(@NonNull byte[] message) implements TssMessage {

    /**
     * Return the byte representation according to {@link TssMessage#bytes()} specification.
     */
    @Override
    public byte[] bytes() {
        return message;
    }
}
