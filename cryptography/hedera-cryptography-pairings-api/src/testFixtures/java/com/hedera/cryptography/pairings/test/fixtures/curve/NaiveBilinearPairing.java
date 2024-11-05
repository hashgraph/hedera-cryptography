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
 * A naive implementation of the BilinearPairing interface for testing purposes.
 * This implementation simply holds two GroupElement instances and provides a method
 * to compare them with another BilinearPairing.
 */
public record NaiveBilinearPairing(@NonNull GroupElement first, @NonNull GroupElement second)
        implements BilinearPairing {

    /**
     * Compares this bilinear pairing with another bilinear pairing.
     *
     * @param other the other bilinear pairing to compare with
     * @return true if both the first and second group elements are equal to the corresponding elements in the other pairing, false otherwise
     */
    @Override
    public boolean compare(@NonNull final BilinearPairing other) {
        Objects.requireNonNull(other, "other must not be null");
        return first.equals(other.first()) && second.equals(other.second());
    }
}
