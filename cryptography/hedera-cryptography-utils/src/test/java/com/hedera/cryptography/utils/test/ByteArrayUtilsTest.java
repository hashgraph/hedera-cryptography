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
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ByteArrayUtilsTest {

    @Test
    void testValidConversion() {
        BigInteger bigInt = new BigInteger("1234567890");
        int size = 32;
        byte[] result = ByteArrayUtils.toLittleEndianBytes(bigInt, size);
        BigInteger convertedBack = ByteArrayUtils.fromLittleEndianBytes(result);
        assertEquals(bigInt, convertedBack);
    }

    @Test
    void testSmallerSize() {
        BigInteger bigInt = new BigInteger("1234567890");
        assertThrows(IllegalArgumentException.class, () -> ByteArrayUtils.toLittleEndianBytes(bigInt, 1));
    }

    @Test
    void testSmallerSizeMultipleBigInts() {
        BigInteger bigInt = new BigInteger("1");
        BigInteger bigInt2 = new BigInteger("2");
        assertThrows(IllegalArgumentException.class, () -> ByteArrayUtils.toLittleEndianBytes(1, bigInt, bigInt2));
        assertDoesNotThrow(() -> ByteArrayUtils.toLittleEndianBytes(2, bigInt, bigInt2));
    }

    @Test
    void testSmallerChunks() {
        assertThrows(IllegalArgumentException.class, () -> ByteArrayUtils.toBigIntegers(new byte[] {1, 2, 3}, 2));
        assertDoesNotThrow(() -> ByteArrayUtils.toBigIntegers(new byte[] {1, 2, 3}, 1));
    }
}
