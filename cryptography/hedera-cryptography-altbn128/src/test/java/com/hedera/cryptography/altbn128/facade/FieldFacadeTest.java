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
import com.hedera.cryptography.altbn128.adapter.FieldLibraryAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FieldFacadeTest {

    private static final int TEST_SIZE = 32;
    private static final int TEST_ERROR_RETURN_CODE = -10;
    private FieldLibraryAdapter fieldLibraryAdapter;
    private FieldFacade fieldFacade;

    @BeforeEach
    void setUp() {
        fieldLibraryAdapter = mock(FieldLibraryAdapter.class);
        when(fieldLibraryAdapter.fieldElementsSize()).thenReturn(TEST_SIZE);
        when(fieldLibraryAdapter.fieldElementsRandomSeedSize()).thenReturn(TEST_SIZE);
        fieldFacade = new FieldFacade(fieldLibraryAdapter);
    }

    @Test
    void testErrorFromBytes() {
        when(fieldLibraryAdapter.fieldElementsFromBytes(any(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.fromBytes(new byte[TEST_SIZE]));
    }

    @Test
    void testErrorFromLong() {
        when(fieldLibraryAdapter.fieldElementsFromLong(eq(10L), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.fromLong(10));
    }

    @Test
    void testErrorFromSeed() {
        when(fieldLibraryAdapter.fieldElementsFromRandomSeed(any(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.fromRandomSeed(new byte[TEST_SIZE]));
    }

    @Test
    void testErrorZero() {
        when(fieldLibraryAdapter.fieldElementsZero(any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.zero());
    }

    @Test
    void testErrorOne() {
        when(fieldLibraryAdapter.fieldElementsOne(any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.one());
    }

    @Test
    void testErrorEquals() {
        when(fieldLibraryAdapter.fieldElementsEquals(any(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, () -> fieldFacade.equals(new byte[TEST_SIZE], new byte[TEST_SIZE]));
    }
}
