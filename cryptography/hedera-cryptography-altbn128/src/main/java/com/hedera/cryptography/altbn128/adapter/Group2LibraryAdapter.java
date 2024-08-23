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
 *  This contract is not Java friendly, and it is defined in a way that is easy to implement in other languages.
 *  All operations return a status code, where 0 mean success, and a non-zero result means a codified error callers must know how to deal with.
 *  As the  code does not guarantee validation of parameters, Input and output parameters must be provided and instantiated accordingly for the invocation to be performed safety.
 *  i.e.:Sending non-null values and correctly instantiated arrays (expected size) is responsibility of the caller.
 *
 */
public interface Group2LibraryAdapter {

    /** The return code that represents that a call succeeded */
    int SUCCESS = 0;
    int GROUP2_ELEMENT_INTERNAL_SIZE = 0;
    int GROUP2_ELEMENT_SEED_SIZE = 0;

    /**
     * Creates a GroupElement byte internal representation from x1,x2,y1,y2 representation of coordinates each of those 32 bytes long.
     * @param x1 a 32 length array containing the first element of coordinate x.
     * @param x2 a 32 length array containing the second element of coordinate x.
     * @param y1 a 32 length array containing the first element of coordinate y.
     * @param y2 a 32 length array containing the first element of coordinate y.
     * @param output a GROUP2_ELEMENT_INTERNAL_SIZE array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2FromCoordinates(final byte[] x1, final byte[] x2, final byte[] y1, final byte[] y2, final byte[] output);


    /**
     * Creates a GroupElement byte internal representation from a seed byte array
     * @param input a byte array of length GROUP2_ELEMENT_SEED_SIZE that will be used as the seed to create the point
     * @param output a GROUP2_ELEMENT_INTERNAL_SIZE array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2FromSeed(final byte[] input, final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the point at infinity
     * @param output a GROUP2_ELEMENT_INTERNAL_SIZE array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2Zero(final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the generator point of the group
     * @param output a GROUP2_ELEMENT_INTERNAL_SIZE array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2Generator(final byte[] output);

    /**
     * returns if two representations are the same
     *
     * @param value a GROUP2_ELEMENT_INTERNAL_SIZE byte array of the internal representation of a point
     * @param other a GROUP2_ELEMENT_INTERNAL_SIZE byte array of the internal representation of a point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    int g2Equals(final byte[] value, final byte[] other);

    /**
     * Returns the byte size of a groupElement internalRepresentation.
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    int g2Size();

    /**
     * @return
     */
    int g2RandomSeedSize();

    /**
     * @return
     */
    int panicTest();

    /**
     * @return
     */
    int g2Add(final byte[] value1, final byte[] value2, final byte[] output);

    /**
     * @return
     */
    int g2ScalarMul(final byte[] value, final byte[] scalar, final byte[] output);

    /**
     * @return
     */
    int g2ToAdHocAffineSerialization(final byte[] input, final byte[] output);

    /**
     * @return
     */
    int g2ToAffineSerialization(final byte[] input, final byte[] output);

    /**
     * @return
     */
    int g2batchScalarMultiplication(final byte[][] scalars, final byte[][] outputs);

    /**
     * @return
     */
    int g2batchAdd(final byte[][] input, final byte[] output);
}
