package com.hedera.cryptography.altbn128;

import com.hedera.cryptography.altbn128.jni.AltBn128FieldElements;

public class AltBn128Exception extends RuntimeException {

    public AltBn128Exception(final int result, final String fieldElementFromLong, final Class<?> aClass) {}
}
