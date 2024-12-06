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

import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.serialization.Serializer;
import java.math.BigInteger;
import java.util.BitSet;

/**
 * Use this class to construct a {@link GroupElement} from an array, or to get the byte[] representation from an instance.
 */
public class GroupElementSerializers {

    /**
     * Constructor
     */
    private GroupElementSerializers() {
        // private constructor for static access
    }

    /**
     * Pairings api based compressed mechanism
     */
    public static Serializer<GroupElement> comrpessSerializer() {
        return groupElement -> {
            if (groupElement.isZero()) {
                return new byte[groupElement.size() / 2];
            }
            var result = BitSet.valueOf(ByteArrayUtils.toByteArray(
                    groupElement.size() / 2, groupElement.getXCoordinate().toArray(new BigInteger[] {})));
            if (groupElement.isYNegative()) {
                result.set(result.size() * Byte.BYTES - 1, true);
            }
            return result.toByteArray();
        };
    }

    /**
     * Default serializer
     */
    public static Serializer<GroupElement> defaultSerializer() {
        return element -> ByteArrayUtils.toByteArray(
                element.size(),
                element.getXCoordinate().toArray(new BigInteger[] {}),
                element.getYCoordinate().toArray(new BigInteger[] {}));
    }

    @Deprecated
    public static class Internals {
        /**
         * Default serializer
         * @return the serializer
         * @apiNote this uses an internal method that is implementation dependant. Use with caution or under know circumstances.
         */
        public static Serializer<GroupElement> internalSerializer() {
            return GroupElement::toBytes;
        }

        /**
         * Arkworks compression serializer
         */
        public static Serializer<GroupElement> arkComrpessSerializer() {
            return GroupElement::compress;
        }
    }
}
