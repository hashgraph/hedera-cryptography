// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.pairings.test.fixtures.curve;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.utils.HashUtils;
import com.hedera.cryptography.utils.ValidationUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Stream;

/**
 * A naive implementation of the Group interface for testing purposes.
 * This implementation provides basic methods to interact with group elements.
 */
public class NaiveGroup implements Group {
    private final PairingFriendlyCurve curve;

    /**
     * Constructs a NaiveGroup with the specified pairing-friendly curve.
     *
     * @param curve the pairing-friendly curve associated with this group
     */
    public NaiveGroup(@NonNull final PairingFriendlyCurve curve) {
        this.curve = Objects.requireNonNull(curve, "curve must not be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        return curve;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public Field field() {
        return curve.field();
    }

    /**
     * Returns a simple generator for demonstration purposes.
     *
     * @return the generator of the group
     */
    @Override
    @NonNull
    public GroupElement generator() {
        return new NaiveGroupElement(this, curve.field(), 1);
    }

    /**
     * Returns the zero element for the group, representing the identity element.
     *
     * @return the zero element of the group
     */
    @Override
    @NonNull
    public GroupElement zero() {
        return new NaiveGroupElement(this, curve.field(), 0);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement msm(final @NonNull List<GroupElement> elements, final @NonNull List<FieldElement> scalars) {
        Objects.requireNonNull(elements, "elements must not be null");
        Objects.requireNonNull(scalars, "scalars must not be null");

        GroupElement result = elements.getFirst().multiply(scalars.getFirst());
        for (int i = 1; i < elementSize(); i++) {
            result = result.add(elements.get(i).multiply(scalars.get(i)));
        }
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement random(@NonNull final byte[] seed) {
        var rng = new Random();
        rng.setSeed(Arrays.hashCode(seed));
        return new NaiveGroupElement(this, curve.field(), rng.nextInt());
    }

    /**
     * Hashes the input bytes to a group element.
     * Uses SHA-256 to hash the input and ensures the result is within the group size.
     *
     * @param input the input bytes
     * @return the group element resulting from the hash
     */
    @Override
    @NonNull
    public GroupElement hashToCurve(@NonNull final byte[] input) {
        final byte[] hash = HashUtils.computeHash(HashUtils.SHA256, input);
        return new NaiveGroupElement(this, curve.field(), Arrays.hashCode(hash));
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement add(@NonNull final Collection<GroupElement> elements) {
        return elements.stream()
                .map(e -> ValidationUtils.expectOrThrow(NaiveGroupElement.class, e))
                .map(GroupElement.class::cast)
                .reduce(this.zero(), GroupElement::add);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public GroupElement fromBytes(@NonNull final byte[] bytes) {
        return new NaiveGroupElement(this, curve.field(), ByteBuffer.wrap(bytes).getInt());
    }

    @NonNull
    @Override
    public GroupElement fromCoordinates(@NonNull final List<BigInteger> x, @NonNull final List<BigInteger> y) {
        return new NaiveGroupElement(
                this,
                curve.field(),
                Stream.concat(x.stream(), y.stream())
                        .reduce(BigInteger.ZERO, BigInteger::add)
                        .intValue());
    }

    @NonNull
    @Override
    public GroupElement fromXCoordinate(@NonNull final List<BigInteger> x, final boolean isYNegative) {
        return new NaiveGroupElement(
                this,
                curve.field(),
                x.stream().reduce(BigInteger.ZERO, BigInteger::add).intValue());
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
    @Override
    public int elementSize() {
        return Integer.BYTES;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int coordinateCofactorCount() {
        return 1;
    }
}
