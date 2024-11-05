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

package com.hedera.cryptography.tss.api;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Allows to obtain a {@code T} element given a shareId
 * @param <T>  The type of the element being mapped to a shareId
 */
public interface TssShareTable<T> {
    /**
     * Allows to obtain a {@code T} element given a shareId
     * Null if the shareId cannot be associated to an element.
     * @param shareId an integer representing the shareId starting in 1. 0 is not a valid shareId
     * @return the T associated to a shareId.
     * @throws IllegalArgumentException if the shareId less or equals to 0 or if it is higher than the total assigned shares
     */
    @NonNull
    T getForShareId(int shareId);
}
