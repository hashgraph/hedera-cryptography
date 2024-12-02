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

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Transformer interface
 * @param <S> source type
 * @param <T> target type
 */
public interface Transformer<S, T> extends Function<S, T> {

    /**
     * Transforms {@code s} into {@code T}
     * @param s source object
     * @return target object
     */
    T transform(S s);

    /**
     * Transforms {@code s} into {@code T}
     * @param s source object
     * @return target object
     */
    default T apply(S s) {
        return transform(s);
    }

    /**
     * transforms a source instance, and then consumes it with consumer
     * @param consumer A consumer of target types
     * @param s source object
     */
    default void consume(@NonNull Consumer<T> consumer, @NonNull S s) {
        consumer.accept(apply(s));
    }
}
