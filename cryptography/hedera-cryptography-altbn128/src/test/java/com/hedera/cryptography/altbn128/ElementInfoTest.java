package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ElementInfoTest {

    @Test
    void unusedBitsCount(){
        assertEquals(2, ElementInfo.FIELD_ELEMENT.getUnusedBits().size(),
                "Field element should have 2 unused bits");
        assertEquals(2, ElementInfo.GROUP1_ELEMENT.getUnusedBits().size(),
                "Group1 element should have 2 unused bits");
        assertEquals(6, ElementInfo.GROUP2_ELEMENT.getUnusedBits().size(),
                "Group2 element should have 6 unused bits");
    }

}