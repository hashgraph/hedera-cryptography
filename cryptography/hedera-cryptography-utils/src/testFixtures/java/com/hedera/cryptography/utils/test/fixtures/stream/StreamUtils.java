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

package com.hedera.cryptography.utils.test.fixtures.stream;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Utility class for operating with streams
 */
public class StreamUtils {
    /**
     *  Creates a stream by zipping two list together. The number of elements of the zipped stream is the one of the list with fewer elements.
     * @param a first list
     * @param b second list
     * @param <A> type for the first list
     * @param <B> type for the second list
     * @return a stream that returns elements from both lists
     */
    @NonNull
    public static <A, B> Stream<Entry<A, B>> zipStream(final @NonNull List<A> a, final @NonNull List<B> b) {
        return IntStream.range(0, Math.min(a.size(), b.size())).mapToObj(i -> Map.entry(a.get(i), b.get(i)));
    }
}
