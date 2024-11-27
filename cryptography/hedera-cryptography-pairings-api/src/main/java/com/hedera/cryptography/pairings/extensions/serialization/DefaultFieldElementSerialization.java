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

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.utils.serialization.Deserializer;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Use this class to construct a {@link FieldElement} from an array, or to get the byte[] representation from an instance.
 */
public class DefaultFieldElementSerialization {

    /**
     * Gets a deserializer.
     * @param field the field.
     * @return a deserializer
     */
    public static Deserializer<FieldElement> getDeserializer(@NonNull final Field field) {
        return new DefaultDeserializer(field);
    }

    /**
     * Gets a serializer.
     * @return a serializer
     */
    public static Serializer<FieldElement> getSerializer() {
        return new DefaultSerializer();
    }

    /**
     * Deserializer
     */
    private static final class DefaultDeserializer implements Deserializer<FieldElement> {
        private final Field field;

        public DefaultDeserializer(@NonNull Field field) {
            this.field = field;
        }

        @Override
        public FieldElement deserialize(final byte[] element) {
            try {
                return field.fromBytes(element);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Cannot deserialize field element", e);
            }
        }
    }

    /**
     * Serializer
     */
    private static final class DefaultSerializer implements Serializer<FieldElement> {

        @Override
        public byte[] serialize(final FieldElement element) {
            return element.toBytes();
        }
    }
}
