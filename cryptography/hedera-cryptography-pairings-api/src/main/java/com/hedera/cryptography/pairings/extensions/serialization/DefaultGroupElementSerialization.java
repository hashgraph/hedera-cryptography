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
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import com.hedera.cryptography.utils.serialization.Transformer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.BitSet;
import java.util.function.Supplier;

/**
 * Use this class to construct a {@link GroupElement} from an array, or to get the byte[] representation from an instance.
 */
public class DefaultGroupElementSerialization {

    /**
     * Constructor
     */
    private DefaultGroupElementSerialization() {
        // private constructor for static access
    }

    /**
     * Default serializer
     * @return the serializer
     * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know circumstances.
     */
    public static Serializer<GroupElement> getSerializer() {
        return GroupElement::toBytes;
    }

    /**
     * Arkworks compression serializer
     */
    public static Serializer<GroupElement> getArkComrpessSerializer() {
        return GroupElement::compress;
    }

    /**
     * Pairings api based compressed mechanism
     */
    public static Serializer<GroupElement> getComrpessSerializer() {
        return groupElement -> {
            if (groupElement.isZero()) {
                return new byte[groupElement.size()];
            }
            var result =
                    BitSet.valueOf(ByteArrayUtils.toByteArray(groupElement.size() / 2, groupElement.getXCoordinate()));
            if (groupElement.isYNegative()) {
                result.flip(result.size() * Byte.BYTES - 1);
            }
            return result.toByteArray();
        };
    }

    /**
     * Default deserializer
     * @param group the group to deserialize to
     * @return the deserializer
     * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know circumstances.
     */
    public static GroupElementDeserializer getDeserializer(@NonNull final Group group) {
        return new ErrorWrappingDeserializer(group::elementSize, group::fromBytes);
    }

    /**
     * Default deserializer
     */
    public static GroupElementDeserializer getCompressedValidatedDeserializer(@NonNull final Group group) {
        return new ErrorWrappingDeserializer(
                () -> group.elementSize() / 2, array -> group.fromBytes(array, true, true));
    }

    /**
     * Default deserializer
     */
    public static GroupElementDeserializer getCompressedNonValidatedDeserializer(@NonNull final Group group) {
        return new ErrorWrappingDeserializer(
                () -> group.elementSize() / 2, array -> group.fromBytes(array, true, false));
    }

    /**
     * Default deserializer
     */
    public static GroupElementDeserializer getNonValidatedDeserializer(@NonNull final Group group) {
        return new ErrorWrappingDeserializer(group::elementSize, array -> group.fromBytes(array, false, true));
    }

    /**
     * Default serializer
     */
    private static final class EIP197Serializer implements Serializer<GroupElement> {

        @Override
        public byte[] serialize(final GroupElement element) {
            return ByteArrayUtils.toByteArray(element.size(), element.getXCoordinate(), element.getYCoordinate());
        }
    }

    /**
     * Default deserializer
     */
    private record ErrorWrappingDeserializer(Supplier<Integer> size, Transformer<byte[], GroupElement> transformer)
            implements GroupElementDeserializer {

        @NonNull
        @Override
        public GroupElement deserialize(@NonNull final byte[] element) {
            try {
                return transformer.transform(element);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Cannot deserialize GroupElement", e);
            }
        }

        @Override
        public int elementSize() {
            return size.get();
        }
    }

    public interface GroupElementDeserializer extends Deserializer<GroupElement> {

        int elementSize();
    }
}
