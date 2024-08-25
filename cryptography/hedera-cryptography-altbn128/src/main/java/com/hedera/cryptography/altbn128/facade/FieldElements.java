/*
 * Copyright (C) 2022-2024 Hedera Hashgraph, LLC
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

import static com.hedera.cryptography.altbn128.adapter.FieldsLibraryAdapter.SUCCESS;

import com.hedera.cryptography.altbn128.AltBn128Exception;
import com.hedera.cryptography.altbn128.adapter.FieldsLibraryAdapter;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * This class acts as a facade that simplifies the interaction for operating with {@code FieldElement} {@code byte[]} representations.
 *  It abstracts the complexities of dealing with return codes and input and output parameters
 *  providing a higher-level interface easier to interact with from Java.
 **/
public final class FieldElements {

    /** the underlying library adapter  */
    private final FieldsLibraryAdapter adapter;
    /** the occupied size in bytes of this of the fieldElements representations. */
    private final int size;
    /** the occupied size in bytes of the random seed.  */
    private final int randomSeedSize;

    /**
     * Creates an instance of this facade.
     * @param fieldsLibraryAdapter the adapter containing the underlying logic.
     */
    public FieldElements(@NonNull final FieldsLibraryAdapter fieldsLibraryAdapter) {
        this.adapter = Objects.requireNonNull(fieldsLibraryAdapter, "adapter must not be null");
        // Caching the value given that this is frequently called
        this.size = adapter.fieldElementsSize();
        // Caching the value given that this is frequently called
        this.randomSeedSize = adapter.fieldElementsRandomSeedSize();
    }

    /**
     * Creates a byte array representation of a fieldElement form a {@code long} parameter.
     * @param inputLong the long parameter to create the representation from
     * @return a byte array of size {@link FieldElements#size()} with the representation of the input
     * @throws AltBn128Exception in case of error
     */
    public byte[] fromLong(final long inputLong) {
        final ByteBuffer bb = ByteBuffer.allocate(size);
        final int result = adapter.fieldElementsFromLong(inputLong, bb.array());
        if (result != SUCCESS) {
            throw new AltBn128Exception(result, "fieldElementFromLong");
        }
        return bb.array();
    }

    /**
     * Creates a byte array representation of a fieldElement form randomly generated seed of size {@link FieldElements#randomSeedSize()}
     * @param seed the randomly generated seed.
     * @return a byte array representation of a fieldElement form seed
     * @throws NullPointerException if the seed is null
     * @throws IllegalArgumentException if the seed is of invalid size
     * @throws AltBn128Exception in case of error
     */
    public byte[] fromRandomSeed(@NonNull final byte[] seed) {
        if (Objects.requireNonNull(seed, "Seed must not be null").length != randomSeedSize) {
            throw new IllegalArgumentException("Invalid random seed");
        }
        final ByteBuffer bb = ByteBuffer.allocate(size);
        final int result = adapter.fieldElementsFromRandomSeed(seed, bb.array());
        if (result != SUCCESS) {
            throw new AltBn128Exception(result, "fieldElementFromRandomSeed");
        }
        return bb.array();
    }

    /**
     * Creates a byte array representation of a fieldElement form another byte array representation
     * TODO: review if this is necessary, what validation is being provided.
     * @return a byte array representation of a fieldElement form the provided byte array representation
     * @param representation the byte representation to validate
     * @throws NullPointerException if the representation is null
     * @throws IllegalArgumentException if the representation is invalid
     * @throws AltBn128Exception in case of error
     */
    public byte[] fromBytes(@NonNull final byte[] representation) {
        if (Objects.requireNonNull(representation, "representation must not be null").length != size) {
            throw new IllegalArgumentException("Invalid byte[] representation");
        }
        final ByteBuffer bb = ByteBuffer.allocate(size);
        final int result = adapter.fieldElementsFromBytes(representation, bb.array());
        if (result != SUCCESS) {
            throw new AltBn128Exception(result, "fieldElementFromBytes");
        }
        return bb.array();
    }

    /**
     * Return a byte array representation of a fieldElement of value 0.
     * @return return a byte array representation of a fieldElement of value 0
     * @throws AltBn128Exception in case of error
     */
    public byte[] zero() {
        final ByteBuffer bb = ByteBuffer.allocate(size);
        final int result = adapter.fieldElementsZero(bb.array());
        if (result != SUCCESS) {
            throw new AltBn128Exception(result, "fieldElementsZero");
        }
        return bb.array();
    }

    /**
     * Return a byte array representation of a fieldElement of value 1.
     * @return return a byte array representation of a fieldElement of value 1
     * @throws AltBn128Exception in case of error
     */
    public byte[] one() {
        final ByteBuffer bb = ByteBuffer.allocate(size);
        final int result = adapter.fieldElementsOne(bb.array());
        if (result != SUCCESS) {
            throw new AltBn128Exception(result, "fieldElementsOne");
        }
        return bb.array();
    }

    /**
     * Returns {@code true} if {@code value} and {@code other} are equals. {@code false} otherwise
     * @param value first value to compare
     * @param other second value to compare
     * @return {@code true} if {@code value} and {@code other} are equals. {@code false} otherwise
     * @throws AltBn128Exception in case of error
     */
    public boolean equals(byte[] value, byte[] other) {
        final int result = adapter.fieldElementsEquals(value, other);
        if (result < SUCCESS) {
            throw new AltBn128Exception(result, "fieldElementsEquals");
        }
        return result == 1;
    }

    /**
     * Return the occupied size in bytes of the fieldElements representations.
     * @return the occupied size in bytes of the fieldElements representations.
     */
    public int size() {
        return this.size;
    }

    /**
     * Return the occupied size in bytes of the random seed.
     * @return the size in bytes for the random seed.
     */
    public int randomSeedSize() {
        return this.randomSeedSize;
    }
}
