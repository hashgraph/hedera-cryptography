// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.pairings.api;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * Represents a mathematical group used in a pairing-based cryptography system.
 *
 * <p>A group in this context is a set of elements (curve points) with operations that satisfies the group properties:
 *  closure, associativity, identity, and invertibility.
 * <p>Curves can be defined by more than one group.
 * <p>This class provides methods to obtain elements belonging to the group represented by the instance.
 *
 * @see GroupElement
 */
public interface Group {
    /**
     * Returns the opposite group of this group
     * <p>
     * If this group is G₁, then the opposite group is G₂, and vice versa.
     *
     * @return the opposite group
     */
    @NonNull
    default Group getOppositeGroup() {
        return getPairingFriendlyCurve().getOtherGroup(this);
    }

    /**
     * Returns the pairing associated with this group
     *
     * @return the pairing associated with this group
     */
    @NonNull
    PairingFriendlyCurve getPairingFriendlyCurve();

    /**
     * Returns the finite field “Fq” associated with the curves of G₁ and G₂.
     *
     * @return the field
     */
    @NonNull
    Field field();

    /**
     * Returns the group's generator.
     * A generator is a point that when multiplied to every different scalar value, it can produce all other elements of the group.
     *
     * @return the group's generator
     */
    @NonNull
    GroupElement generator();

    /**
     * Creates a new group element with value 0
     *
     * @return the new group element
     */
    @NonNull
    GroupElement zero();

    /**
     * Performs multi-scalar multiplication of a list of {@link GroupElement}s and {@link FieldElement}.
     * <p>
     * Computes the result of the operation:
     * <pre>
     *     Result = k1 * P1 + k2 * P2 + ... + kn * Pn
     * </pre>
     * where:
     * <ul>
     *   <li><code>k<sub>i</sub></code> are scalar values (FieldElement)</li>
     *   <li><code>P<sub>i</sub></code> are points on the elliptic curve, (GroupElements)</li>
     *   <li><code>+</code> denotes point addition on the elliptic curve</li>
     *   <li><code>*</code> denotes scalar multiplication on the elliptic curve</li>
     * </ul>
     *
     * @param elements  a list of curve points
     * @param scalars a list of scalar values corresponding to each point
     * @return the resulting {@link GroupElement} after performing the multi-scalar multiplication
     * @throws IllegalArgumentException if the lengths of {@code scalars} and {@code points} do not match
     * @throws NullPointerException if {@code scalars} or {@code points} is null, or contains null elements
     */
    @NonNull
    GroupElement msm(@NonNull List<GroupElement> elements, @NonNull List<FieldElement> scalars);

    /**
     * Performs multi-scalar multiplication of a list of {@link GroupElement}s and a {@code long} array.
     * <p>
     * Computes the result of the operation:
     * <pre>
     *     Result = k1 * P1 + k2 * P2 + ... + kn * Pn
     * </pre>
     * where:
     * <ul>
     *   <li><code>k<sub>i</sub></code> are scalar values (long)</li>
     *   <li><code>P<sub>i</sub></code> are points on the elliptic curve, (GroupElements)</li>
     *   <li><code>+</code> denotes point addition on the elliptic curve</li>
     *   <li><code>*</code> denotes scalar multiplication on the elliptic curve</li>
     * </ul>
     *
     * @param elements  a list of curve points
     * @param scalars an array of scalar values corresponding to each point
     * @return the resulting {@link GroupElement} after performing the multi-scalar multiplication
     * @throws IllegalArgumentException if the lengths of {@code scalars} and {@code points} do not match
     * @throws NullPointerException if {@code scalars} or {@code points} is null, or contains null elements
     */
    @NonNull
    default GroupElement msm(@NonNull List<GroupElement> elements, @NonNull long... scalars) {
        Objects.requireNonNull(elements, "elements must not be null");
        Objects.requireNonNull(scalars, "scalars must not be null");
        if (scalars.length != elements.size()) {
            throw new IllegalArgumentException("Number of scalars and elements do not match");
        }
        return this.msm(
                elements,
                Arrays.stream(scalars).mapToObj(this.field()::fromLong).toList());
    }

    /**
     * Creates a group element from a rng
     *
     * @param random the rng to use
     * @return the new group element
     */
    @NonNull
    default GroupElement random(Random random) {
        byte[] seed = new byte[this.seedSize()];
        random.nextBytes(seed);
        return random(seed);
    }

    /**
     * Creates a group element from a seed
     *
     * @param seed the seed to generate the element from
     * @return the new group element
     */
    @NonNull
    GroupElement random(@NonNull byte[] seed);

    /**
     * Hashes an unbounded length input to a group element
     *
     * @param input the input to be hashed
     * @return the new group element
     */
    @NonNull
    GroupElement hashToCurve(@NonNull byte[] input);

    /**
     * Adds a collection of group elements together
     *
     * @param elements the collection of elements to add together
     * @return a new group element which is the sum the collection of elements
     */
    @NonNull
    GroupElement add(@NonNull Collection<GroupElement> elements);

    /**
     * Creates a group element from its internal encoding.
     * The serialization is implementation specific and should not be relied upon to be consistent across different versions of the library.
     *
     * @param bytes serialized form
     * @return the new group element
     * @throws IllegalArgumentException if the byte representation is not a valid point on the curve
     * @deprecated This method is implementation specific and should not be used.
     */
    @NonNull
    @Deprecated
    GroupElement fromBytes(@NonNull byte[] bytes);

    /**
     * Creates a group element from its x and y coordinates
     *
     * @param x the x coordinate
     * @param y the y coordinate
     * @return the new group element
     */
    @NonNull
    GroupElement fromCoordinates(@NonNull final List<BigInteger> x, @NonNull final List<BigInteger> y);

    /**
     * Creates a group element from its x coordinates
     *
     * @param x the x coordinate
     * @param isYNegative indicates which of the two possible Y coordinates to select.
     *                    Also referred as odd/even.
     * @return the new group element
     */
    @NonNull
    GroupElement fromXCoordinate(@NonNull final List<BigInteger> x, boolean isYNegative);

    /**
     * Gets the size in bytes of the seed necessary to generate a new element
     *
     * @return the size of a seed needed to generate a new element
     */
    int seedSize();

    /**
     * Gets the size in bytes of a group element returned by {@link GroupElement#toBytes()}
     *
     * @return the size in bytes
     */
    int elementSize();

    /**
     * Returns the number of cofactors in a coordinate for this group (the number of integers needed to represent a
     * coordinate)
     *
     * @return the number of cofactors
     */
    int coordinateCofactorCount();
}
