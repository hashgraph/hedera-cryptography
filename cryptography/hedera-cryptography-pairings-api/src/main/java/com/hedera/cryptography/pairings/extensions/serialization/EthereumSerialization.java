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

public class EthereumSerialization {
    private final BigInteger fieldModulus;
    private final int fieldModulusByteCount;

    private final PairingFriendlyCurve curve;

    public EthereumSerialization(final PairingFriendlyCurve curve) {
        this.curve = curve;
        this.fieldModulus = curve.field().modulus();
        this.fieldModulusByteCount = fieldModulus.toByteArray().length;
    }

    public byte[] serializeField(final FieldElement element) {
        return ensureLength(element.toBigInteger().toByteArray(), fieldModulusByteCount);
    }

    public byte[] serializeGroup(final GroupElement element) {
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

    public FieldElement deserializeField(final byte[] bytes) {
        final BigInteger bi = new BigInteger(1, bytes);
        isValid(bi);
        return curve.field().fromBigInteger(bi);
    }

    public GroupElement deserializeGroup(final byte[] bytes, final Group group) {
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

    public Serializer<FieldElement> fieldSerializer() {
        return this::serializeField;
    }

    public Serializer<GroupElement> groupSerializer() {
        return this::serializeGroup;
    }

    public Deserializer<FieldElement> fieldDeserializer() {
        return this::deserializeField;
    }

    public Deserializer<GroupElement> groupDeserializer(@NonNull final Group group) {
        return bytes -> deserializeGroup(bytes, group);
    }

    public void isValid(final BigInteger bigInteger) {
        if (bigInteger.compareTo(fieldModulus) >= 0) {
            throw new IllegalArgumentException("Serialized element is bigger than the field modulus");
        }
    }

    public static void checkBytes(final byte[] bytes, final int expectedLength) {
        Objects.requireNonNull(bytes, "bytes must not be null");
        if (bytes.length != expectedLength) {
            throw new IllegalArgumentException("Invalid length, expected " + expectedLength + " bytes");
        }
    }

    private static byte[] ensureLength(final byte[] bytes, final int length) {
        if (bytes.length == length) {
            return bytes;
        }
        final byte[] result = new byte[length];
        System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        return result;
    }
}
