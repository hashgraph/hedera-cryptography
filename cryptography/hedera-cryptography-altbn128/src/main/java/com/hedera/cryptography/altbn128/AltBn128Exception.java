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

package com.hedera.cryptography.altbn128;

import com.hedera.cryptography.pairings.api.PairingsException;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A {@link PairingsException} In the context of this implementation.
 * Stores the result code returned by the underlying arkworks operation, and the operation resulting in error.
 */
public class AltBn128Exception extends PairingsException {

    /**
     * The result code from the rust operation
     */
    final transient int result;
    /**
     * The underlying arkworks operation
     */
    final transient String operationName;

    /**
     * Creates a {@link PairingsException} In the context of this implementation.
     * @param result The result code from the rust operation
     * @param operationName The underlying arkworks operation
     */
    public AltBn128Exception(final int result, final @NonNull String operationName) {
        super("result=" + result + ", operationName=" + operationName);
        this.result = result;
        this.operationName = operationName;
    }
}
