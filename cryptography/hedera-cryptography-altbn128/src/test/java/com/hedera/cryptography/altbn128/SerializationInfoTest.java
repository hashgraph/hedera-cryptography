package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SerializationInfoTest {

    @Test
    void unusedBitsCount(){
        assertEquals(2, SerializationInfo.FIELD_ELEMENT.getUnusedBits().size());
        assertEquals(2, SerializationInfo.GROUP1_ELEMENT.getUnusedBits().size());
        assertEquals(6, SerializationInfo.GROUP2_ELEMENT.getUnusedBits().size());
    }

}