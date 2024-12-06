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

import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Transformer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

public class GroupElementDeserializers {

    /**
     * Serializes an elliptic curve group element into a byte array following the MCL format.
     * The MCL format ensures compatibility with cryptographic libraries that use
     * pairing-friendly elliptic curves, such as BN254 and BLS12-381. This format includes:
     * <ul>
     *   <li>each coordinate is N values of size M where M coincides with the EC field element size</li>
     *   <li>Coordinates are represented in their uncompressed form</li>
     *   <li>Big-endian byte order is used for encoding the coordinates.</li>
     *   <li>Zero is represented by an all zero values.</li>
     * </ul>
     */
    public static GroupElementDeserializer defaultDeserializer(@NonNull final Group group) {
        return new ErrorWrappingDeserializer(group.elementSize(), new MCLTransformer(group));
    }

    /**
     * Serializes an elliptic curve group element into a byte array following the MCL compressed format.
     * The MCL format ensures compatibility with cryptographic libraries that use
     * pairing-friendly elliptic curves, such as BN254 and BLS12-381. This format includes:
     * <ul>
     *   <li>Big-endian byte order is used for encoding the coordinates.</li>
     *   <li>Compression reduces the size by encoding only the X-coordinate and a
     *       single bit (last bit) to represent the sign of Y (if applicable).</li>
     * </ul>
     * This implementation adheres to the internal representation and serialization format
     * used by MCL to ensure interoperability with cryptographic systems and protocols
     * that rely on MCL-based libraries.
     */
    public static GroupElementDeserializer compressedDeserializer(@NonNull final Group group) {
        return new ErrorWrappingDeserializer(group.elementSize() / 2, new CompressedTransformer(group));
    }

    /**
     * A bunch of deserializers for internal use and benchmarking if necessary
     *
     * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know
     * circumstances.
     */
    @Deprecated
    public static class Internals {

        /**
         * Internal deserializer
         *
         * @param group the group to deserialize to
         * @return the deserializer
         * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know
         * circumstances.
         */
        public static GroupElementDeserializer internalDeserializer(@NonNull final Group group) {
            return new ErrorWrappingDeserializer(group.elementSize(), group::fromBytes);
        }

        /**
         * Internal deserializer.
         * It does not perform the curve equation validation nor the subgroup validation
         *
         * @param group the group to deserialize to
         * @return the deserializer
         * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know
         * circumstances.
         */
        public static GroupElementDeserializer internalNonValidatedDeserializer(@NonNull final Group group) {
            return new ErrorWrappingDeserializer(group.elementSize(), array -> group.fromBytes(array, false, true));
        }

        /**
         * Internal deserializer.
         * Returns the implementation dependent representation in compressed format
         *
         * @param group the group to deserialize to
         * @return the deserializer
         * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know
         * circumstances.
         */
        public static GroupElementDeserializer internalCompressedDeserializer(@NonNull final Group group) {
            return new ErrorWrappingDeserializer(group.elementSize() / 2, array -> group.fromBytes(array, true, true));
        }

        /**
         * Internal deserializer.
         * Returns the implementation dependent representation in compressed format
         * It does not perform the curve equation validation nor the subgroup validation
         * @param group the group to deserialize to
         * @return the deserializer
         * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know
         * circumstances.
         */
        public static GroupElementDeserializer internalCompressedNonValidatedDeserializer(@NonNull final Group group) {
            return new ErrorWrappingDeserializer(group.elementSize() / 2, array -> group.fromBytes(array, true, false));
        }
    }

    public interface GroupElementDeserializer extends Deserializer<GroupElement> {
        int size();
    }

    /**
     * Default deserializer
     */
    private record MCLTransformer(Group group) implements Transformer<byte[], GroupElement> {
        @Override
        public GroupElement transform(final byte[] s) {
            final var individualSize = group.field().elementSize();
            final List<BigInteger> xs = new ArrayList<>();
            for (int i = 0; i < group.elementSize() / 2; i += individualSize) {
                xs.add(new BigInteger(Arrays.copyOfRange(s, i, i + individualSize)));
            }
            final List<BigInteger> ys = new ArrayList<>();
            for (int i = group.elementSize() / 2; i < group.elementSize(); i += individualSize) {
                ys.add(new BigInteger(Arrays.copyOfRange(s, i, i + individualSize)));
            }
            try {
                return group.fromCoordinates(xs, ys);
            } catch (
                    IllegalArgumentException
                            e) { // Leveraging the fact that the point is not in the curve in most curves
                if (BitSet.valueOf(s).isEmpty()) {
                    return group.zero();
                }
                throw e;
            }
        }
    }

    private record CompressedTransformer(Group group) implements Transformer<byte[], GroupElement> {
        @Override
        public GroupElement transform(final byte[] s) {
            final var individualSize = group.field().elementSize();
            final var bitSet = BitSet.valueOf(s);
            if (bitSet.isEmpty()) {
                return group.zero();
            }
            final var isYNegative = bitSet.get(bitSet.length() - 1);
            bitSet.clear(bitSet.length() - 1);
            final var xs = new ArrayList<BigInteger>();
            final var rep = bitSet.toByteArray();
            for (int i = 0; i < s.length; i += individualSize) {
                xs.add(new BigInteger(Arrays.copyOfRange(rep, i, i + individualSize)));
            }
            return group.fromX(xs, isYNegative);
        }
    }

    private record ErrorWrappingDeserializer(int size, Transformer<byte[], GroupElement> transformer)
            implements GroupElementDeserializer {

        @NonNull
        @Override
        public GroupElement deserialize(@NonNull final byte[] element) {
            if (element.length != size) {
                throw new IllegalStateException("Invalid group element representation");
            }
            try {
                return transformer.transform(element);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Cannot deserialize GroupElement", e);
            }
        }
    }
}
