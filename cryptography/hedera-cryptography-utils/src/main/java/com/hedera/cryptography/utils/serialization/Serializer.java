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

package com.hedera.cryptography.utils.serialization;

/**
 * Serializer interface.
 *
 * @param <S> Source type
 */
@FunctionalInterface
public interface Serializer<S> extends Transformer<S, byte[]> {

    /**
     * "Serializes" a source type {@code S} into a target type {@code T}
     * Usually T is a byte[] but this interface is left open to allow the inclusion of 3rd party serialization such as protobuf, etc.
     * @param s source object
     * @return a T object.
     */
    byte[] serialize(S s);

    /**
     * {@inheritDoc}
     */
    @Override
    default byte[] transform(S s) {
        return serialize(s);
    }
}
