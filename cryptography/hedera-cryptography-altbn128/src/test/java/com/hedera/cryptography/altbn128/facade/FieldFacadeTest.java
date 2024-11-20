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

package com.hedera.cryptography.altbn128.facade;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.hedera.cryptography.altbn128.AltBn128Exception;
import com.hedera.cryptography.altbn128.adapter.FieldElementsLibraryAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FieldFacadeTest {

    private static final int TEST_SIZE = 32;
    private static final int TEST_ERROR_RETURN_CODE = -10;
    private FieldElementsLibraryAdapter fieldElementsLibraryAdapter;
    private FieldFacade fieldFacade;

    @BeforeEach
    void setUp() {
        fieldElementsLibraryAdapter = mock(FieldElementsLibraryAdapter.class);
        when(fieldElementsLibraryAdapter.fieldElementsSize()).thenReturn(TEST_SIZE);
        when(fieldElementsLibraryAdapter.randomSeedSize()).thenReturn(TEST_SIZE);
        fieldFacade = new FieldFacade(fieldElementsLibraryAdapter);
    }

    @Test
    void testErrorFromBytes() {
        when(fieldElementsLibraryAdapter.fieldElementsFromBytes(any(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.fromBytes(new byte[TEST_SIZE], true));
    }

    @Test
    void testErrorFromLong() {
        when(fieldElementsLibraryAdapter.fieldElementsFromLong(eq(10L), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.fromLong(10));
    }

    @Test
    void testErrorFromSeed() {
        when(fieldElementsLibraryAdapter.fieldElementsFromRandomSeed(any(), any()))
                .thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.fromRandomSeed(new byte[TEST_SIZE]));
    }

    @Test
    void testErrorZero() {
        when(fieldElementsLibraryAdapter.fieldElementsZero(any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.zero());
    }

    @Test
    void testErrorOne() {
        when(fieldElementsLibraryAdapter.fieldElementsOne(any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.one());
    }

    @Test
    void testErrorEquals() {
        when(fieldElementsLibraryAdapter.fieldElementsEquals(any(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.equals(new byte[TEST_SIZE], new byte[TEST_SIZE]));
    }
}
