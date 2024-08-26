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

package com.hedera.cryptography.altbn128.facade;

import com.hedera.cryptography.altbn128.AltBn128Exception;
import com.hedera.cryptography.altbn128.adapter.FieldLibraryAdapter;
import com.hedera.cryptography.altbn128.adapter.Group2LibraryAdapter;
import com.hedera.cryptography.altbn128.common.BigIntegerUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * This class acts as a facade that simplifies the interaction for operating specifically with the second {@code Group}
 *  and its {@code GroupElement} {@code byte[]} representations.
 *  It abstracts the complexities of dealing with return codes and input and output parameters
 *  providing a higher-level interface easier to interact with from Java.
 **/
public final class Group2Facade {

    /** The underlying library adapter */
    private final Group2LibraryAdapter adapter;
    /** The occupied size in bytes of the GroupElement representations */
    private final int size;
    /** The occupied size in bytes of the random seed */
    private final int randomSeedSize;
    /** The occupied size in bytes of the scalar */
    private final int fieldElementsSize;

    /**
     * Creates an instance of this facade.
     * @param adapter the adapter containing the underlying logic.
     */
    public Group2Facade(@NonNull final Group2LibraryAdapter adapter, final int fieldElementsSize) {
        this.adapter = Objects.requireNonNull(adapter, "adapter must not be null");
        this.size = adapter.g2Size();
        this.randomSeedSize = adapter.g2RandomSeedSize();
        this.fieldElementsSize = fieldElementsSize;
    }

    /**
     * Creates a Group2 point from coordinates.
     * @param x1 the first element of the x-coordinate.
     * @param x2 the second element of the x-coordinate.
     * @param y1 the first element of the y-coordinate.
     * @param y2 the second element of the y-coordinate.
     * @return the byte array representation of the Group2 point.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] fromCoordinates(
            @NonNull final BigInteger x1,
            @NonNull final BigInteger x2,
            @NonNull final BigInteger y1,
            @NonNull final BigInteger y2) {
        byte[] x1Array = BigIntegerUtils.toLittleEndianBytes(x1, Group2LibraryAdapter.POINT_COORDINATE_BYTE_SIZE);
        byte[] x2Array = BigIntegerUtils.toLittleEndianBytes(x2, Group2LibraryAdapter.POINT_COORDINATE_BYTE_SIZE);
        byte[] y1Array = BigIntegerUtils.toLittleEndianBytes(y1, Group2LibraryAdapter.POINT_COORDINATE_BYTE_SIZE);
        byte[] y2Array = BigIntegerUtils.toLittleEndianBytes(y2, Group2LibraryAdapter.POINT_COORDINATE_BYTE_SIZE);

        final byte[] output = new byte[size];
        final int result = adapter.g2FromCoordinates(x1Array, x2Array, y1Array, y2Array, output);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2FromCoordinates");
        }
        return output;
    }

    /**
     * Creates a Group2 point from a random seed.
     * @param seed the byte array seed.
     * @return the byte array representation of the Group2 point.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] fromSeed(@NonNull final byte[] seed) {
        validateSize(seed, randomSeedSize, "Invalid random seed size");
        final byte[] output = new byte[size];
        final int result = adapter.g2FromSeed(seed, output);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2FromSeed");
        }
        return output;
    }

    /**
     * Returns the Group2 point at infinity.
     * @return the byte array representation of the point at infinity.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] zero() {
        final byte[] output = new byte[size];
        final int result = adapter.g2Zero(output);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Zero");
        }
        return output;
    }

    /**
     * Returns the Group2 generator point.
     * @return the byte array representation of the generator point.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] generator() {
        final byte[] output = new byte[size];
        final int result = adapter.g2Generator(output);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Generator");
        }
        return output;
    }

    /**
     * Checks if two Group2 points are equal.
     * @param point1 the first point.
     * @param point2 the second point.
     * @return true if points are equal, false otherwise.
     * @throws AltBn128Exception in case of error.
     */
    public boolean equals(@NonNull final byte[] point1, @NonNull final byte[] point2) {
        if (point1.length != point2.length) {
            return false;
        }
        final int result = adapter.g2Equals(point1, point2);
        if (result < Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Equals");
        }
        return result == 1;
    }

    /**
     * Adds two Group2 points together.
     * @param point1 the first point.
     * @param point2 the second point.
     * @return the byte array representation of the resulting point.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] add(@NonNull final byte[] point1, @NonNull final byte[] point2) {
        validateSize(point1, size, "Invalid point size");
        validateSize(point2, size, "Invalid point size");
        final byte[] output = new byte[size];
        final int result = adapter.g2Add(point1, point2, output);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Add");
        }
        return output;
    }

    /**
     * Performs scalar multiplication between a Group2 point and a scalar.
     * @param point the Group2 point representation.
     * @param scalar the scalar.
     * @return the byte array representation of the resulting point.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] scalarMul(@NonNull final byte[] point, @NonNull final byte[] scalar) {
        validateSize(point, size, "Invalid point size");
        validateSize(scalar, fieldElementsSize, "Invalid scalar size");
        final byte[] output = new byte[size];
        final int result = adapter.g2ScalarMul(point, scalar, output);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2ScalarMul");
        }
        return output;
    }

    /**
     * Converts an affine serialized point back into its internal representation.
     * This method takes a byte array representing the affine serialization of a point
     * and converts it back to its internal representation.
     *
     * @param bytes a byte array of {@link Group2LibraryAdapter#g2Size()} to validate if is a right point
     * @return if valid the same {@code bytes} array of {@link Group2LibraryAdapter#g2Size()} containing the internal representation of the point
     * @throws NullPointerException if the bytes is null
     * @throws IllegalArgumentException if the bytes is of invalid size or the point does not belong to the curve
     * @throws AltBn128Exception in case of error.
     */
    public byte[] fromBytes(@NonNull final byte[] bytes) {
        validateSize(Objects.requireNonNull(bytes, "bytes must not be null"), this.size, "Invalid representation size");

        int result = adapter.g2Bytes(bytes);
        if (result == Group2LibraryAdapter.NOT_IN_CURVE) {
            throw new IllegalArgumentException("The point is not in curve");
        } else if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Bytes");
        }

        return bytes;
    }

    /**
     * Sums a collection of points and returns the resulting point.
     * This method takes a list of points (each in internal representation) and returns
     * the point that is the result of summing all the points together.
     *
     * @param points a byte matrix representing a list of N byte arrays of {@link Group2LibraryAdapter#g2Size()} representing each point
     * @return a byte array of {@link Group2LibraryAdapter#g2Size()} containing representation of the resulting point.
     * @throws NullPointerException if points is null
     * @throws AltBn128Exception in case of an error during the batch addition
     */
    public byte[] batchAdd(@NonNull final byte[][] points) {
        Objects.requireNonNull(points, "points must not be null");
        final byte[] output = new byte[size];
        int result = adapter.g2batchAdd(points, output);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2batchAdd");
        }
        return output;
    }

    /**
     * Validates the size of a byte array.
     * @param data the byte array to validate.
     * @param expectedSize the expected size of the array.
     * @param message the error message to throw.
     */
    private static void validateSize(
            @Nullable final byte[] data, final int expectedSize, @NonNull final String message) {
        if (Objects.requireNonNull(data, "data must not be null").length != expectedSize) {
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Return the occupied size in bytes of this group2Elements representations.
     * @return the occupied size in bytes of this group2Elements representations.
     */
    public int size() {
        return this.size;
    }

    /**
     * Return the occupied size in bytes of the random seed.
     * @return the size in bytes for the random seed.
     */
    public int randomSeedSize() {
        return this.randomSeedSize;
    }

    /**
     * multiplies each scalar in a collection for the generator point and returns the resulting points.
     * This method takes a list of scalars (each in internal representation) and returns
     * the list of point that is the result of multiplying the scalar for the generator point.
     *
     * @param scalars a byte matrix representing a list of N scalars of {@link FieldLibraryAdapter#fieldElementsSize()}  representing each scalar
     * @return N points each as a byte array of {@link Group2LibraryAdapter#g2Size()} containing representation of the resulting point.
     * @throws NullPointerException if scalars is null
     * @throws AltBn128Exception in case of an error during the batch addition
     */
    public byte[][] batchMultiply(final byte[][] scalars) {
        Objects.requireNonNull(scalars, "scalars must not be null");
        final byte[][] array = new byte[scalars.length][this.size];
        int result = adapter.g2batchScalarMultiplication(scalars, array);
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2batchScalarMultiplication");
        }
        return array;
    }
}
