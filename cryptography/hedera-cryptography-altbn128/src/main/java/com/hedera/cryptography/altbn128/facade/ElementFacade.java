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

package com.hedera.cryptography.altbn128.facade;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * This interface acts as a facade that simplifies the interaction for operating with the elements for alt-bn-128
 */
public sealed interface ElementFacade permits FieldFacade, GroupFacade {

    /**
     * Return the occupied size in bytes of the random seed.
     *
     * @return the size in bytes for the random seed.
     */
    int randomSeedSize();

    /**
     * Creates an element from a random seed. The size of the seed must be equal to the size returned by
     * {@link #randomSeedSize()}.
     *
     * @param seed the seed to use
     * @return the element created from the seed
     */
    @NonNull
    byte[] fromRandomSeed(@NonNull final byte[] seed);

    /**
     * Returns the zero element.
     *
     * @return the zero element
     */
    @NonNull
    byte[] zero();

    /**
     * Checks the equality of two elements.
     *
     * @param value the first element
     * @param other the second element
     * @return true if the elements are equal, otherwise false
     */
    boolean equals(@NonNull byte[] value, @NonNull byte[] other);

    /**
     * Reads the element representation and checks if it's valid.
     *
     * @param representation the representation of the element
     * @return the (possibly modified) representation of the element
     */
    @NonNull
    byte[] fromBytes(@NonNull final byte[] representation);
}
