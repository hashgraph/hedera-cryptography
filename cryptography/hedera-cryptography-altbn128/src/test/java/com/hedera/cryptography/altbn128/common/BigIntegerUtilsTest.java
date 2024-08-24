package com.hedera.cryptography.altbn128.common;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class BigIntegerUtilsTest {

    @Test
    void test () {
        BigInteger bigInt = new BigInteger("1234567890"); // Example BigInteger
        int size = 32;
            byte[] result = BigIntegerUtils.toLittleEndianBytes(bigInt, size);
            System.out.println("Little-endian byte array: " + Arrays.toString(result));

            BigInteger convertedBack = BigIntegerUtils.fromLittleEndianBytes(result);
            System.out.println("Converted back to BigInteger: " + convertedBack);
            assertEquals(bigInt, convertedBack);

    }
}