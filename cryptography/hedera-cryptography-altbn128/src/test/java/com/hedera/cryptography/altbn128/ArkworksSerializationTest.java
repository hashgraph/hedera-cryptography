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

package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class ArkworksSerializationTest {

    @Test
    void unusedBitsCount() {
        assertEquals(
                2,
                ArkworksSerialization.FIELD_ELEMENT.getUnusedBits().size(),
                "Field element should have 2 unused bits");
        assertEquals(
                2,
                ArkworksSerialization.GROUP1_ELEMENT.getUnusedBits().size(),
                "Group1 element should have 2 unused bits");
        assertEquals(
                6,
                ArkworksSerialization.GROUP2_ELEMENT.getUnusedBits().size(),
                "Group2 element should have 6 unused bits");
    }

    @Test
    void coordinatesAndBack() {
        final BigInteger x = new BigInteger("703710");
        final BigInteger y = new BigInteger("65535");

        final byte[] bytes = ArkworksSerialization.coordinatesToBytes(List.of(x, y));

        assertEquals(x, ArkworksSerialization.getCoordinate(bytes, true).getFirst());
        assertEquals(y, ArkworksSerialization.getCoordinate(bytes, false).getFirst());
    }

    @Test
    void coordinatesToBytes() {
        final String hexExpected =
                "aabbccddeeff00000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000";
        final byte[] bytes = ArkworksSerialization.coordinatesToBytes(
                List.of(new BigInteger("281401388481450"), new BigInteger("1")));
        System.out.println(HexFormat.of().formatHex(bytes));
        assertEquals(
                hexExpected, HexFormat.of().formatHex(bytes), "Coordinates should be converted to bytes correctly");
    }
}
