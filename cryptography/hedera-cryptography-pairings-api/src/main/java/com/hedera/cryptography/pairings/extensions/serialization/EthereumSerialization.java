// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.pairings.extensions.serialization;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Serialization for elements that conforms to <a href="https://eips.ethereum.org/EIPS/eip-197#encoding"> EIP-197</a>
 */
public class EthereumSerialization {
    /** The field modulus */
    private final BigInteger fieldModulus;
    /** The number of bytes needed to represent the field modulus */
    private final int fieldModulusByteCount;
    /** The curve being (de)serialized */
    private final PairingFriendlyCurve curve;

    /**
     * Constructor
     *
     * @param curve the curve to (de)serialize
     */
    public EthereumSerialization(@NonNull final PairingFriendlyCurve curve) {
        this.curve = Objects.requireNonNull(curve);
        this.fieldModulus = curve.field().modulus();
        this.fieldModulusByteCount = fieldModulus.toByteArray().length;
    }

    /**
     * Serialize a field element
     *
     * @param element the element to serialize
     * @return the serialized element
     */
    @NonNull
    public byte[] serializeField(@NonNull final FieldElement element) {
        return ensureLength(Objects.requireNonNull(element).toBigInteger().toByteArray(), fieldModulusByteCount);
    }

    /**
     * Serialize a group element
     *
     * @param element the element to serialize
     * @return the serialized element
     */
    @NonNull
    public byte[] serializeGroup(@NonNull final GroupElement element) {
        Objects.requireNonNull(element);
        final BigInteger[] bigInts = Stream.concat(element.getXCoordinate().stream(), element.getYCoordinate().stream())
                .toArray(BigInteger[]::new);
        final byte[] output = new byte[fieldModulusByteCount * bigInts.length];
        for (int i = 0; i < bigInts.length; i++) {
            final byte[] biBytes = bigInts[i].toByteArray();
            System.arraycopy(
                    biBytes,
                    0,
                    output,
                    i * fieldModulusByteCount + (fieldModulusByteCount - biBytes.length),
                    biBytes.length);
        }

        return output;
    }

    /**
     * Deserialize a field element
     *
     * @param bytes the serialized element
     * @return the deserialized element
     */
    @NonNull
    public FieldElement deserializeField(@NonNull final byte[] bytes) {
        checkBytes(bytes, fieldModulusByteCount);
        final BigInteger bi = new BigInteger(1, bytes);
        isValid(bi);
        return curve.field().fromBigInteger(bi);
    }

    /**
     * Deserialize a group element
     *
     * @param bytes the serialized element
     * @param group the group of the element
     * @return the deserialized element
     */
    @NonNull
    public GroupElement deserializeGroup(@NonNull final byte[] bytes, @NonNull final Group group) {
        checkBytes(bytes, 2 * group.coordinateCofactorCount() * fieldModulusByteCount);

        final List<BigInteger> bigInts = new ArrayList<>();
        for (int i = 0; i < bytes.length; i += fieldModulusByteCount) {
            bigInts.add(new BigInteger(1, bytes, i, fieldModulusByteCount));
        }
        if (bigInts.stream().allMatch(bi -> bi.equals(BigInteger.ZERO))) {
            return group.zero();
        }
        bigInts.forEach(this::isValid);

        return group.fromCoordinates(
                bigInts.subList(0, bigInts.size() / 2), bigInts.subList(bigInts.size() / 2, bigInts.size()));
    }

    /**
     * Get the field serializer
     *
     * @return the field serializer
     */
    @NonNull
    public Serializer<FieldElement> fieldSerializer() {
        return this::serializeField;
    }

    /**
     * Get the group serializer
     *
     * @return the group serializer
     */
    @NonNull
    public Serializer<GroupElement> groupSerializer() {
        return this::serializeGroup;
    }

    /**
     * Get the field deserializer
     *
     * @return the field deserializer
     */
    @NonNull
    public Deserializer<FieldElement> fieldDeserializer() {
        return this::deserializeField;
    }

    /**
     * Get the group deserializer
     *
     * @param group the group to deserialize to
     * @return the group deserializer
     */
    @NonNull
    public Deserializer<GroupElement> groupDeserializer(@NonNull final Group group) {
        return bytes -> deserializeGroup(bytes, group);
    }

    private void isValid(@NonNull final BigInteger bigInteger) {
        if (bigInteger.compareTo(fieldModulus) >= 0) {
            throw new IllegalArgumentException("Serialized element is bigger than the field modulus");
        }
    }

    private static void checkBytes(@NonNull final byte[] bytes, final int expectedLength) {
        Objects.requireNonNull(bytes, "bytes must not be null");
        if (bytes.length != expectedLength) {
            throw new IllegalArgumentException("Invalid length, expected " + expectedLength + " bytes");
        }
    }

    @NonNull
    private static byte[] ensureLength(@NonNull final byte[] bytes, final int length) {
        if (bytes.length == length) {
            return bytes;
        }
        final byte[] result = new byte[length];
        System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        return result;
    }
}
