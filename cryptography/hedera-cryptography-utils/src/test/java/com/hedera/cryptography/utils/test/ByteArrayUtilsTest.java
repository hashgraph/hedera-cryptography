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

package com.hedera.cryptography.utils.test;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.utils.ByteArrayUtils;
import org.junit.jupiter.api.Test;

class ByteArrayUtilsTest {

    @Test
    void testSmallerChunks() {
        assertThrows(IllegalArgumentException.class, () -> ByteArrayUtils.toBigIntegers(new byte[] {1, 2, 3}, 2));
        assertDoesNotThrow(() -> ByteArrayUtils.toBigIntegers(new byte[] {1, 2, 3}, 1));
    }

    @Test
    void byteReversalTest() {
        assertArrayEquals(
                new byte[] {8, 7, 6, 5, 4, 3, 2, 1},
                ByteArrayUtils.reverseByteOrder(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}));
        assertArrayEquals(
                new byte[] {0, 1, 5, 4, 3, 2, 6, 7},
                ByteArrayUtils.reverseByteOrder(new byte[] {0, 1, 2, 3, 4, 5, 6, 7}, 2, 6));
        assertArrayEquals(
                new byte[] {4, 3, 2, 1, 0, 5, 6, 7},
                ByteArrayUtils.reverseByteOrder(new byte[] {0, 1, 2, 3, 4, 5, 6, 7}, 0, 5));
        assertArrayEquals(
                new byte[] {0, 1, 2, 7, 6, 5, 4, 3},
                ByteArrayUtils.reverseByteOrder(new byte[] {0, 1, 2, 3, 4, 5, 6, 7}, 3, 8));
    }
}
