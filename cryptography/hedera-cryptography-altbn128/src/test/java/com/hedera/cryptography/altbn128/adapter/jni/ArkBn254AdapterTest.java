package com.hedera.cryptography.altbn128.adapter.jni;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.altbn128.AltBN128CurveGroup;
import com.hedera.cryptography.altbn128.adapter.GroupElementsLibraryAdapter;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class ArkBn254AdapterTest {

    @Test
    void groupElementsFromHashTest(){
        // setup
        final ArkBn254Adapter adapter = ArkBn254Adapter.getInstance();
        final int groupId = AltBN128CurveGroup.GROUP1.getId();
        final byte[] hash = new byte[32];
        final byte[] output = new byte[adapter.groupElementsSize(groupId)];

        // success case
        new Random(0).nextBytes(hash);
        final int result1 = adapter.groupElementsFromHash(groupId, hash, output);
        assertEquals(GroupElementsLibraryAdapter.SUCCESS, result1, "we expect the method to return success");
        assertNotEquals(0, IntStream.range(0, output.length).map(i -> output[i]).sum(),
                "the output is expected to be populated, if it was untouched, its sum would be 0");

        // cleanup
        Arrays.fill(hash, (byte) 0);
        Arrays.fill(output, (byte) 0);

        // failure case
        final int result2 = adapter.groupElementsFromHash(groupId, hash, output);
        assertNotEquals(GroupElementsLibraryAdapter.SUCCESS, result2, "an array of all zeros should not be a valid hash");
    }

}