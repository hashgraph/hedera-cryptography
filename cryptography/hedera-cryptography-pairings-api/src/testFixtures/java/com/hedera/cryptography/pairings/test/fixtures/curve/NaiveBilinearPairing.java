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

package com.hedera.cryptography.pairings.test.fixtures.curve;

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

/**
 * Without having an actual elliptic curve implementation, this curve is not supporting the bilinear pairing operation.
 */
public record NaiveBilinearPairing(@NonNull GroupElement first, @NonNull GroupElement second)
        implements BilinearPairing {

    /**
     * This curve is not supporting the bilinear pairing operation.
     *
     * @param other the other bilinear pairing to compare with
     * @return true if both the first and second group elements are equal to the corresponding elements in the other pairing, false otherwise
     */
    @Override
    public boolean compare(@NonNull final BilinearPairing other) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
