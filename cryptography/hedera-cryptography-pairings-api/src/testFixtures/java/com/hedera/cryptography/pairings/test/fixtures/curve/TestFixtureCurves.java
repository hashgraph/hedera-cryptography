package com.hedera.cryptography.pairings.test.fixtures.curve;

import com.hedera.cryptography.pairings.api.Curve;

public enum TestFixtureCurves implements Curve {
    NAIVE_CURVE((byte) 0);

    /**
     * An internal unique id per curve.
     */
    final byte id;

    TestFixtureCurves(byte id) {
        this.id = id;
    }

    @Override
    public byte getId() {
        return id;
    }
}
