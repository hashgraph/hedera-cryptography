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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.FieldElement;
import org.junit.jupiter.api.Test;

class AltBn128FieldElementTest {

    @Test
    void testEquality() {
        final AltBn128Field mock = mock(AltBn128Field.class);
        final byte[] thizz = new byte[32];
        final byte[] anotherOne = thizz.clone();
        anotherOne[0] = 1;
        final byte[] anotherTwo = thizz.clone();
        anotherTwo[0] = 2;

        var value = new AltBn128FieldElement(thizz, mock);
        var value2 = new AltBn128FieldElement(anotherOne, mock(AltBn128Field.class));
        var value3 = new AltBn128FieldElement(anotherTwo, mock);
        var value4 = new AltBn128FieldElement(thizz, mock(AltBn128Field.class));
        var value5 = new AltBn128FieldElement(new byte[30], mock);

        assertEquals(value, value);
        assertTrue(value.equals(value));
        assertNotEquals(value, value2);
        assertFalse(value.equals(value2));
        assertFalse(value2.equals(value));
        assertNotEquals(value, value3);
        assertFalse(value.equals(value3));
        assertFalse(value3.equals(value));
        assertNotEquals(value, value4);
        assertFalse(value.equals(value4));
        assertFalse(value4.equals(value));
        assertNotEquals(value, mock(FieldElement.class));
        assertNotEquals(value, value5);
        assertFalse(value.equals(value5));
        assertFalse(value5.equals(value));
    }
}
