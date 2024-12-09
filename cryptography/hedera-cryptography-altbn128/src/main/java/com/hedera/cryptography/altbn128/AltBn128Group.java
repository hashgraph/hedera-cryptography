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

package com.hedera.cryptography.altbn128;

import com.hedera.cryptography.altbn128.adapter.jni.ArkBn254Adapter;
import com.hedera.cryptography.altbn128.facade.GroupFacade;
import com.hedera.cryptography.altbn128.facade.GroupFacade.ToBytesFlags;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.utils.HashUtils;
import com.hedera.cryptography.utils.HashUtils.HashCalculator;
import com.hedera.cryptography.utils.ValidationUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.security.Security;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The implementation of the two {@link Group} of {@link com.hedera.cryptography.pairings.api.curves.KnownCurves#ALT_BN128}
 */
public class AltBn128Group implements Group {
    /** String ID to use for obtaining the digest algorithm */
    private static final String KECCAK_256 = "Keccak-256";
    /** The number of times to rehash in {@link #hashToCurve(byte[])} */
    private static final int HASH_RETRIES = 255;

    private final Field field;
    private final GroupFacade facade;
    private final AltBN128CurveGroup group;

    static {
        // add provider only if it's not in the JVM
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Creates an instance of a {@link GroupFacade} for this implementation.
     * @param group the actual group represented by this instance
     * @param field the scalar field
     */
    public AltBn128Group(final @NonNull AltBN128CurveGroup group, final @NonNull AltBn128Field field) {
        this.group = Objects.requireNonNull(group, "group must not be null");
        this.field = Objects.requireNonNull(field, "field must not be null");
        this.facade = new GroupFacade(
                group.getId(),
                ArkBn254Adapter.getInstance(),
                ArkBn254Adapter.getInstance().fieldElementsSize());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @NonNull
    @Override
    public Field field() {
        return field;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement generator() {
        return new AltBn128GroupElement(this, facade.generator());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement zero() {
        return new AltBn128GroupElement(this, facade.zero());
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement random(@NonNull final byte[] seed) {
        return new AltBn128GroupElement(this, facade.fromRandomSeed(seed));
    }

    /**
     * Creates a group element from its serialized encoding, validating if the point is in the curve.
     *
     * @throws NullPointerException if the bytes is null
     * @throws IllegalArgumentException if the bytes is of invalid size or the point does not belong to the curve
     * @throws AltBn128Exception in case of error.
     * @deprecated Implementation specific
     */
    @NonNull
    @Override
    @Deprecated
    public GroupElement fromBytes(@NonNull final byte[] bytes) {
        return new AltBn128GroupElement(this, facade.fromBytes(bytes));
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement fromCoordinates(@NonNull final List<BigInteger> x, @NonNull final List<BigInteger> y) {
        final var coordinates = Stream.concat(
                        Objects.requireNonNull(x, "x must not be null").stream(),
                        Objects.requireNonNull(y, "y must not be null").stream())
                .toList();
        final byte[] bytes = ArkworksSerialization.coordinatesToBytes(this.elementSize(), coordinates);
        return new AltBn128GroupElement(this, facade.fromBytes(bytes, ToBytesFlags.DEFAULT));
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement fromXCoordinate(@NonNull final List<BigInteger> x, final boolean isYNegative) {
        byte[] bytes = ArkworksSerialization.coordinatesToBytes(this.elementSize() / 2, x);
        if (isYNegative) {
            ArkworksSerialization.setYNegativeFlag(bytes, true);
        }
        return new AltBn128GroupElement(this, facade.fromBytes(bytes, ToBytesFlags.IS_COMPRESSED));
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement hashToCurve(@NonNull final byte[] input) {
        final HashCalculator calculator = HashUtils.getHashCalculator(KECCAK_256);
        // hash the input and try to find a valid group element
        // hash the hash until we find a valid group element
        byte[] candidate = input;
        for (int i = 0; i < HASH_RETRIES; i++) {
            calculator.append(candidate);
            candidate = calculator.hash();
            final byte[] element = facade.hashToGroup(candidate);
            if (element != null) {
                return new AltBn128GroupElement(this, element);
            }
        }
        throw new AltBn128Exception("Could not find a valid group element after %d tries".formatted(HASH_RETRIES));
    }

    /**
     * {@inheritDoc}
     * @throws IllegalArgumentException if any of the elements is null or not an instance of {@link AltBn128GroupElement}
     */
    @NonNull
    @Override
    public GroupElement add(@NonNull final Collection<GroupElement> elements) {
        Objects.requireNonNull(elements, "elements must not be null");
        final byte[][] allElements = elements.stream()
                .map(e -> AltBn128GroupElement.isSameAltBn128GroupElement(this, e))
                .map(AltBn128GroupElement::getRepresentation)
                .toArray(byte[][]::new);
        return new AltBn128GroupElement(this, facade.batchAdd(allElements));
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement msm(final @NonNull List<GroupElement> elements, final @NonNull List<FieldElement> scalars) {
        Objects.requireNonNull(elements, "elements must not be null");
        Objects.requireNonNull(scalars, "scalars must not be null");
        if (scalars.size() != elements.size()) {
            throw new IllegalArgumentException("Number of scalars and elements do not match");
        }
        final byte[][] allElements = elements.stream()
                .map(e -> AltBn128GroupElement.isSameAltBn128GroupElement(this, e))
                .map(AltBn128GroupElement::getRepresentation)
                .toArray(byte[][]::new);

        final byte[][] allScalars = scalars.stream()
                .map(e -> ValidationUtils.expectOrThrow(AltBn128FieldElement.class, e))
                .map(AltBn128FieldElement::getRepresentation)
                .toArray(byte[][]::new);
        final byte[] groupElements = facade.msm(allScalars, allElements);
        return new AltBn128GroupElement(this, groupElements);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public GroupElement msm(final @NonNull List<GroupElement> elements, final @NonNull long... scalars) {
        Objects.requireNonNull(elements, "elements must not be null");
        Objects.requireNonNull(scalars, "scalars must not be null");
        if (scalars.length != elements.size()) {
            throw new IllegalArgumentException("Number of scalars and elements do not match");
        }
        final byte[][] allElements = elements.stream()
                .map(e -> AltBn128GroupElement.isSameAltBn128GroupElement(this, e))
                .map(AltBn128GroupElement::getRepresentation)
                .toArray(byte[][]::new);

        final byte[] groupElements = facade.msm(scalars, allElements);
        return new AltBn128GroupElement(this, groupElements);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof final AltBn128Group that)) {
            return false;
        }
        return group == that.group;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(group);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int seedSize() {
        return facade.randomSeedSize();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int elementSize() {
        return facade.size();
    }

    /**
     * Returns the facade.
     * Internal method
     * @return the facade
     */
    GroupFacade getFacade() {
        return facade;
    }

    /**
     * Returns the curve group.
     * Internal method
     * @return the curve group.
     */
    AltBN128CurveGroup getGroup() {
        return group;
    }
}
