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

package com.hedera.cryptography.altbn128.adapter;

/**
 * This interface defines a contract and any third party library that provides the functionality must adhere to.
 *  This contract is not Java friendly, and it is defined in a way that is easy to implement in other languages such as rust.
 *  All operations return a status code, where 0 mean success, and a non-zero result means a codified error callers must know how to deal with.
 *  As the native code does not guarantee validation of parameters, Input and output parameters must be provided and instantiated accordingly for the invocation to be performed safety.
 *  i.e.:Sending non-null values and correctly instantiated arrays (expected size) is responsibility of the caller.
 *
 */
public interface LibraryAdapter {

    /** The return code that represents that a call succeeded */
    int SUCCESS = 0;

    /**
     * The the byte size of a field element object.
     * TODO Maybe better to request the value from rust
     */
    int FIELD_ELEMENTS_SIZE = 32;
    /**
     * the byte size of the random seed to use.
     * TODO Maybe better to request the value from rust
     */
    int FIELD_ELEMENTS_RANDOM_SEED_SIZE = 32;

    /**
     * Creates a new random scalar from a seed value
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param inputSeed       the byte seed to be used to create the new scalar
     * @param output          the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int fieldElementsFromRandomSeed(final int groupAssignment, final byte[] inputSeed, final byte[] output);

    /**
     * Creates a new scalar from a long
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param inputLong       the long to be used to create the new scalar
     * @param output          the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int fieldElementsFromLong(final int groupAssignment, final long inputLong, final byte[] output);

    /**
     * Determines if the input representation is a valida FieldElement
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param input           the that represents the scalar
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int fieldElementsFromBytes(final int groupAssignment, final byte[] input, final byte[] output);

    /**
     * Creates a new zero value scalar
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int fieldElementsZero(final int groupAssignment, final byte[] output);

    /**
     * Creates a new one value scalar.
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int fieldElementsOne(final int groupAssignment, final byte[] output);

    /**
     * returns if two representations are the same
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param value           the that represents a scalar
     * @param other          the that represents another scalar
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    int fieldElementsEquals(final int groupAssignment, final byte[] value, final byte[] other);

    /**
     * Returns the byte size of a field element object.
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    default int fieldElementsSize() {
        return FIELD_ELEMENTS_SIZE;
    }

    /**
     * Returns the byte size of the random seed to use.
     *
     * @return the byte size of the random seed to use.
     */
    default int fieldElementsRandomSeedSize() {
        return FIELD_ELEMENTS_RANDOM_SEED_SIZE;
    }
}
