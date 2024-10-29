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

package com.hedera.cryptography.altbn128.adapter.jni;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.hedera.cryptography.altbn128.AltBN128CurveGroup;
import com.hedera.cryptography.altbn128.adapter.GroupElementsLibraryAdapter;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class ArkBn254AdapterTest {

    /**
     * Tests the {@link ArkBn254Adapter#groupElementsFromXCoordinate(int, byte[], byte[])} method.
     */
    @Test
    void groupElementsFromXCoordinateTest() {
        // setup
        final ArkBn254Adapter adapter = ArkBn254Adapter.getInstance();
        final int groupId = AltBN128CurveGroup.GROUP1.getId();
        final byte[] output = new byte[adapter.groupElementsSize(groupId)];

        // success case
        final byte[] xCoordinate = HexFormat.of().parseHex("60b420bb3851d9d47acb933dbe70399bf6c92da33af01d4fb770e98c0325f41d");
        final int result1 = adapter.groupElementsFromXCoordinate(groupId, xCoordinate, output);
        assertEquals(GroupElementsLibraryAdapter.SUCCESS, result1, "we expect the method to return success");
        assertNotEquals(
                0,
                IntStream.range(0, output.length).map(i -> output[i]).sum(),
                "the output is expected to be populated, if it was untouched, its sum would be 0");

        // cleanup
        Arrays.fill(output, (byte) 0);

        // failure case
        final int result2 = adapter.groupElementsFromXCoordinate(groupId, new byte[32], output);
        assertNotEquals(
                GroupElementsLibraryAdapter.SUCCESS,
                result2,
                "an array of all zeros should not be a valid x coordinate");
    }
}
