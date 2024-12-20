// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.pairings.test.fixtures.curve;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Random;

/**
 * A naive implementation of the Field interface for testing purposes.
 * This implementation provides basic methods to create field elements from various inputs.
 */
public class NaiveField implements Field {

    private final PairingFriendlyCurve curve;

    /**
     * Constructs a NaiveField with the specified pairing-friendly curve.
     *
     * @param curve the pairing-friendly curve associated with this field
     */
    public NaiveField(@NonNull final PairingFriendlyCurve curve) {
        this.curve = Objects.requireNonNull(curve, "curve must not be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public FieldElement random(@NonNull final Random random) {
        Objects.requireNonNull(random, "random must not be null");
        return fromLong(random.nextLong());
    }

    /**
     * Creates a field element from a long value.
     * The value is reduced modulo the prime modulus.
     *
     * @param inputLong the long value
     * @return a field element representing the long value
     */
    @Override
    @NonNull
    public FieldElement fromLong(final long inputLong) {
        return new NaiveFieldElement(this, inputLong);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public FieldElement random(@NonNull final byte[] seed) {
        return this.fromBytes(seed);
    }

    /**
     * Creates a field element from a byte array.
     * The value is reduced modulo the prime modulus.
     *
     * @param bytes the byte array
     * @return a field element representing the byte array
     */
    @Override
    @NonNull
    public FieldElement fromBytes(@NonNull final byte[] bytes) {
        return new NaiveFieldElement(this, ByteBuffer.wrap(bytes).getInt());
    }

    /**
     * Creates a field element from a BigInteger.
     * The value is reduced modulo the prime modulus.
     *
     * @param bigInteger the BigInteger
     * @return a field element representing the BigInteger
     */
    @Override
    @NonNull
    public FieldElement fromBigInteger(@NonNull final BigInteger bigInteger) {
        return new NaiveFieldElement(this, bigInteger.intValueExact());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int elementSize() {
        return Integer.BYTES;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int seedSize() {
        return Integer.BYTES;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public BigInteger modulus() {
        return BigInteger.valueOf(Integer.MAX_VALUE + 1L);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        return curve;
    }
}
