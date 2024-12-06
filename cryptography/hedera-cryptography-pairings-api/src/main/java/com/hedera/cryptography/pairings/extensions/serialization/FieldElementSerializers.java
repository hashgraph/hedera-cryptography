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
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.serialization.Serializer;
import java.math.BigInteger;

/**
 * Use this class to construct a {@link FieldElement} from an array, or to get the byte[] representation from an instance.
 */
public class FieldElementSerializers {

    /**
     * Constructor
     */
    private FieldElementSerializers() {
        // private constructor for static access
    }

    /**
     * Gets a serializer.
     * @return a serializer
     */
    public static Serializer<FieldElement> defaultSerializer() {
        return element -> ByteArrayUtils.toByteArray(element.size(), new BigInteger[] {element.toBigInteger()});
    }
}
