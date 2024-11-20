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
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;

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
     * Default deserializer
     * @param group the group to deserialize to
     * @return the deserializer
     */
    public static Deserializer<GroupElement> getDeserializer(@NonNull final Group group) {
        return new DefaultGroupElementSerialization.DefaultDeserializer(group);
    }
    /**
     * Default serializer
     * @return the serializer
     */
    public static Serializer<GroupElement> getSerializer() {
        return new DefaultGroupElementSerialization.DefaultSerializer();
    }

    /**
     * Default deserializer
     */
    public static Deserializer<GroupElement> getCompressedDeserializer(Group group) {
        return new DefaultGroupElementSerialization.CompressedDeserializer(group);
    }

    /**
     * Default serializer
     */
    public static Serializer<GroupElement> getCompressSerializer() {
        return new DefaultGroupElementSerialization.CompressedSerializer();
    }

    /**
     * Default serializer
     */
    private static final class DefaultSerializer implements Serializer<GroupElement> {

        @Override
        public byte[] serialize(final GroupElement element) {
            return element.toBytes();
        }
    }

    /**
     * Default deserializer
     */
    private record DefaultDeserializer(Group group) implements Deserializer<GroupElement> {

        @NonNull
        @Override
        public GroupElement deserialize(@NonNull final byte[] element) {
            try {
                return group.fromBytes(element);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Cannot deserialize GroupElement", e);
            }
        }
    }

    private record CompressedDeserializer(Group group) implements Deserializer<GroupElement> {

        @NonNull
        @Override
        public GroupElement deserialize(@NonNull final byte[] element) {
            try {
                return group.fromCompressed(element);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Cannot deserialize GroupElement", e);
            }
        }
    }

    private static final class CompressedSerializer implements Serializer<GroupElement> {

        @Override
        public byte[] serialize(final GroupElement element) {
            return element.compress();
        }
    }
}
