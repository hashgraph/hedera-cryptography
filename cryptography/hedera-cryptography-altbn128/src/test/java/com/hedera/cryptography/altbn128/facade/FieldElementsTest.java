package com.hedera.cryptography.altbn128.facade;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.hedera.cryptography.altbn128.AltBn128Exception;
import com.hedera.cryptography.altbn128.adapter.LibraryAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FieldElementsTest {

    private static final int TEST_SIZE = 32;
    private static final int TEST_ERROR_RETURN_CODE = -10;
    private LibraryAdapter libraryAdapter;
    private FieldElements fieldElements;

    @BeforeEach
    void setUp() {
        libraryAdapter = mock(LibraryAdapter.class);
        fieldElements = new FieldElements(libraryAdapter, 0);
        when(libraryAdapter.fieldElementsSize()).thenReturn(TEST_SIZE);
        when(libraryAdapter.fieldElementsRandomSeedSize()).thenReturn(TEST_SIZE);
    }
    @Test
    void testErrorFromBytes(){
        when(libraryAdapter.fieldElementsFromBytes(anyInt(), any(),any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, ()-> fieldElements.fromBytes(new byte[TEST_SIZE]));
    }

    @Test
    void testErrorFromLong(){
        when(libraryAdapter.fieldElementsFromLong(anyInt(), eq(10L),any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, ()-> fieldElements.fromLong(10));
    }

    @Test
    void testErrorZero(){
        when(libraryAdapter.fieldElementsZero(anyInt(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, ()-> fieldElements.zero());
    }

    @Test
    void testErrorOne(){
        when(libraryAdapter.fieldElementsOne(anyInt(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, ()-> fieldElements.one());
    }

    @Test
    void testErrorEquals(){
        when(libraryAdapter.fieldElementsEquals(anyInt(), any(), any())).thenReturn(TEST_ERROR_RETURN_CODE);
        assertThrows(AltBn128Exception.class, ()-> fieldElements.equals(new byte[TEST_SIZE],new byte[TEST_SIZE]));
    }
}