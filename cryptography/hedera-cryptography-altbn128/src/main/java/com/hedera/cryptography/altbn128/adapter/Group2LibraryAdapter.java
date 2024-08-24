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
 * This interface defines a contract and any third party library that provides the functionality for handling Elliptic Curve Group and Points must adhere to.
 *
 *  @apiNote This contract is not Java friendly, and it is defined in a way that is easy to implement in other languages.
 *  All operations return a status code, where 0 mean success, and a non-zero result means a codified error callers must know how to deal with.
 *  As the  code does not guarantee validation of parameters, Input and output parameters must be provided and instantiated accordingly for the invocation to be performed safety.
 *  i.e.:Sending non-null values and correctly instantiated arrays (expected size) is responsibility of the caller.
 * @implSpec Implementations are not forced to perform validations on the expected size of the arrays or the nullity of the parameters, so that remains a callers responsibility.
 */
public interface Group2LibraryAdapter {

    /** The return code that represents that a call succeeded */
    int SUCCESS = 0;

    int POINT_BYTE_SIZE = 32;

    /**
     * Creates a GroupElement byte internal representation from x1,x2,y1,y2 representation of coordinates each of those 32 bytes long.
     *
     * @param x1 a POINT_BYTE_SIZE length array containing the first element of coordinate x.
     * @param x2 a POINT_BYTE_SIZE length array containing the second element of coordinate x.
     * @param y1 a POINT_BYTE_SIZE length array containing the first element of coordinate y.
     * @param y2 a POINT_BYTE_SIZE length array containing the first element of coordinate y.
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2FromCoordinates(final byte[] x1, final byte[] x2, final byte[] y1, final byte[] y2, final byte[] output);

    /**
     * Creates a GroupElement byte internal representation from a seed byte array
     * @param input a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2FromSeed(final byte[] input, final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the point at infinity
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2Zero(final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the generator point of the group
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2Generator(final byte[] output);

    /**
     * returns if two representations are the same
     *
     * @param value a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param other a byte array of {@link Group2LibraryAdapter#g2Size()}  that contains the internal represents the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    int g2Equals(final byte[] value, final byte[] other);

    /**
     * Returns the byte size of a groupElement internal representation.
     *
     * @return
     */
    int g2Size();

    /**
     * Returns the byte size of a groupElement affine representation.
     *
     * @return
     */
    int g2AffineSize();

    /**
     * Returns the byte size of the expected seed byte array for creating random points on the curve.
     *
     * @return
     */
    int g2RandomSeedSize();

    /**
     * panic function invocation
     * TODO: remove
     * @return nothing this function panics
     */
    int panicTest();

    /**
     * Returns the addition of code {@code value} and  {@code other}.
     *
     * @param value a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param other a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    int g2Add(final byte[] value, final byte[] other, final byte[] output);

    /**
     * Returns the scalar multiplication between code {@code point} and {@code scalar}.
     *
     * @param point a byte array of {@link Group2LibraryAdapter#g2Size()} that will be used as the seed to create the point
     * @param scalar a byte array of {@link FieldsLibraryAdapter#fieldElementsSize()}} that contains the representation of the scalar
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2ScalarMul(final byte[] point, final byte[] scalar, final byte[] output);

    /**
     * Returns the serialization of the affine representation of the point
     *
     * @param point a byte array of {@link Group2LibraryAdapter#g2Size()} that will be used as the seed to create the point
     * @param output a {@link Group2LibraryAdapter#g2AffineSize()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2ToAdHocAffineSerialization(final byte[] point, final byte[] output);

    /**
     * Returns the serialization of the affine representation of the point
     *
     * @param point a byte array of {@link Group2LibraryAdapter#g2Size()} that will be used as the seed to create the point
     * @param output a {@link Group2LibraryAdapter#g2AffineSize()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2ToAffineSerialization(final byte[] point, final byte[] output);

    /**
     * Returns the result of the multiplication of the {@link Group2LibraryAdapter#g2Generator(byte[])} for each scalar in the {@code scalars} list
     *
     * @param scalars a byte matrix representing a list of N byte arrays of {@link FieldsLibraryAdapter#fieldElementsSize()}} size each representing a scalar
     * @param outputs a byte matrix of N byte arrays {@link Group2LibraryAdapter#g2AffineSize()} size to hold the internal representation of the generator point times the scalar in {@code scalars}
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2batchScalarMultiplication(final byte[][] scalars, final byte[][] outputs);

    /**
     * Returns the point that is the result of the total sum a collection of points
     *
     * @param input a byte matrix representing a list of N byte arrays of {@link Group2LibraryAdapter#g2Size()} representing each point
     * @param output a {@link Group2LibraryAdapter#g2AffineSize()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2batchAdd(final byte[][] input, final byte[] output);

    /**
     * Creates a GroupElement byte internal representation from an external affine representation of {@link Group2LibraryAdapter#g2AffineSize()} bytes long.
     *
     * @param input  a {@link Group2LibraryAdapter#g2AffineSize()} size array  affine representation of bytes long
     * @param output a {@link Group2LibraryAdapter#g2Size()} size array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int g2FromAffine(final byte[] input, final byte[] output);
}
