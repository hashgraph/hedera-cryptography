package com.hedera.cryptography.altbn128.facade;

import com.hedera.cryptography.altbn128.AltBn128Exception;
import com.hedera.cryptography.altbn128.adapter.Group2LibraryAdapter;
import com.hedera.cryptography.altbn128.common.BigIntegerUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Objects;

public final class Group2 {

    /** The underlying library adapter */
    private final Group2LibraryAdapter adapter;
    /** The occupied size in bytes of the GroupElement representations */
    private final int size;
    /** The occupied size in bytes of the affine representation */
    private final int affineSize;
    /** The occupied size in bytes of the random seed */
    private final int randomSeedSize;
    /** The occupied size in bytes of the scalar */
    private final int fieldElementsSize;

    /**
     * Creates an instance of this facade.
     * @param adapter the adapter containing the underlying logic.
     */
    public Group2(@NonNull final Group2LibraryAdapter adapter, final int fieldElementsSize) {
        this.adapter = Objects.requireNonNull(adapter, "adapter must not be null");
        // Cache frequently called values
        this.size = adapter.g2Size();
        this.affineSize = adapter.g2AffineSize();
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
    public byte[] fromCoordinates(@NonNull final BigInteger x1, @NonNull final BigInteger x2,
                                  @NonNull final BigInteger y1, @NonNull final BigInteger y2) {
        byte[] x1Array = BigIntegerUtils.toLittleEndianBytes(x1, Group2LibraryAdapter.POINT_BYTE_SIZE);
        byte[] x2Array =BigIntegerUtils.toLittleEndianBytes(x2, Group2LibraryAdapter.POINT_BYTE_SIZE);
        byte[] y1Array =BigIntegerUtils.toLittleEndianBytes(y1, Group2LibraryAdapter.POINT_BYTE_SIZE);
        byte[] y2Array =BigIntegerUtils.toLittleEndianBytes(y2, Group2LibraryAdapter.POINT_BYTE_SIZE);

        final ByteBuffer output = ByteBuffer.allocate(size);
        final int result = adapter.g2FromCoordinates(x1Array, x2Array, y1Array, y2Array, output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2FromCoordinates");
        }
        return output.array();
    }

    /**
     * Creates a Group2 point from a random seed.
     * @param seed the byte array seed.
     * @return the byte array representation of the Group2 point.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] fromSeed(@NonNull final byte[] seed) {
        validateSize(seed, randomSeedSize, "Invalid random seed size");
        final ByteBuffer output = ByteBuffer.allocate(size);
        final int result = adapter.g2FromSeed(seed, output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2FromSeed");
        }
        return output.array();
    }

    /**
     * Returns the Group2 point at infinity.
     * @return the byte array representation of the point at infinity.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] zero() {
        final ByteBuffer output = ByteBuffer.allocate(size);
        final int result = adapter.g2Zero(output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Zero");
        }
        return output.array();
    }

    /**
     * Returns the Group2 generator point.
     * @return the byte array representation of the generator point.
     * @throws AltBn128Exception in case of error.
     */
    public byte[] generator() {
        final ByteBuffer output = ByteBuffer.allocate(size);
        final int result = adapter.g2Generator(output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Generator");
        }
        return output.array();
    }

    /**
     * Checks if two Group2 points are equal.
     * @param point1 the first point.
     * @param point2 the second point.
     * @return true if points are equal, false otherwise.
     * @throws AltBn128Exception in case of error.
     */
    public boolean equals(@NonNull final byte[] point1, @NonNull final byte[] point2) {
        if(point1.length != point2.length) {
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
        final ByteBuffer output = ByteBuffer.allocate(size);
        final int result = adapter.g2Add(point1, point2, output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2Add");
        }
        return output.array();
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
        final ByteBuffer output = ByteBuffer.allocate(size);
        final int result = adapter.g2ScalarMul(point, scalar, output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2ScalarMul");
        }
        return output.array();
    }

    /**
     * Returns the affine serialization of a point.
     * This method converts the internal representation of a point to its affine representation
     * and returns it as a byte array.
     *
     * @param point the Group2 point representation.
     * @return a byte array of {@link Group2LibraryAdapter#g2AffineSize()} containing the affine serialized point
     * @throws NullPointerException if the point is null
     * @throws IllegalArgumentException if the point is of invalid size
     * @throws AltBn128Exception in case of an error during serialization
     */
    public byte[] toAffineSerialization(@NonNull final byte[] point) {
        validateSize(point, size, "Invalid point size");
        final ByteBuffer output = ByteBuffer.allocate(this.affineSize);
        int result = adapter.g2ToAffineSerialization(point, output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2ToAffineSerialization");
        }
        return output.array();
    }

    /**
     * Converts an affine serialized point back into its internal representation.
     * This method takes a byte array representing the affine serialization of a point
     * and converts it back to its internal representation.
     *
     * @param affinePoint a byte array of {@link Group2LibraryAdapter#g2AffineSize()} containing the affine serialized point
     * @return a byte array of {@link Group2LibraryAdapter#g2Size()} containing the internal representation of the point
     * @throws NullPointerException if the affinePoint is null
     * @throws IllegalArgumentException if the affinePoint is of invalid size
     * @throws AltBn128Exception in case of an error during deserialization
     */
    public byte[] fromAffineSerialization(@NonNull final byte[] affinePoint) {
        validateSize(Objects.requireNonNull(affinePoint, "Affine point must not be null"), this.affineSize, "Affine point");

        final ByteBuffer output = ByteBuffer.allocate(this.affineSize);
        int result = adapter.g2FromAffine(affinePoint, output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2FromAffineBytes");
        }
        return output.array();
    }


    /**
     * Sums a collection of points and returns the resulting point.
     * This method takes a list of points (each in internal representation) and returns
     * the point that is the result of summing all the points together.
     *
     * @param points a byte matrix representing a list of N byte arrays of {@link Group2LibraryAdapter#g2Size()} representing each point
     * @return a byte array of {@link Group2LibraryAdapter#g2Size()} containing the affine serialized point
     * @throws NullPointerException if the input points or any of its elements are null
     * @throws IllegalArgumentException if any point in the input is of invalid size
     * @throws AltBn128Exception in case of an error during the batch addition
     */
    public byte[] batchAdd(@NonNull final byte[][] points) {
        Objects.requireNonNull(points, "points must not be null");
        final ByteBuffer output = ByteBuffer.allocate(this.size);
        int result = adapter.g2batchAdd(points, output.array());
        if (result != Group2LibraryAdapter.SUCCESS) {
            throw new AltBn128Exception(result, "g2batchAdd");
        }
        return output.array();
    }

    /**
     * Validates the size of a byte array.
     * @param data the byte array to validate.
     * @param expectedSize the expected size of the array.
     * @param message the error message to throw.
     */
    private static void validateSize(@Nullable final byte[] data, final int expectedSize, @NonNull final String message) {
        if (Objects.requireNonNull(data, "data must not be null").length != expectedSize) {
            throw new IllegalArgumentException(message);
        }
    }

    public int size() {
        return this.size;
    }


    public int randomSeedSize() {
        return this.randomSeedSize;
    }
}
