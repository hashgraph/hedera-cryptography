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

package com.hedera.cryptography.utils.test.fixtures;

import edu.umd.cs.findbugs.annotations.NonNull;

public class ByteUtils {
    /**
     * Creates a binary string representation of the following byte array
     * @param bytes the byte array to represent
     * @return a string representation of the byte array
     */
    @SuppressWarnings("unused") // useful for debugging
    public static @NonNull String toBinaryString(@NonNull final byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
            sb.append(' ');
        }
        return sb.toString();
    }
}
