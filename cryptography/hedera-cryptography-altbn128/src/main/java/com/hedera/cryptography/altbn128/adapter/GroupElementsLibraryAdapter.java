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
public interface GroupElementsLibraryAdapter extends RandomElementsAdapter {

    /** The return code that represents that a call succeeded */
    int SUCCESS = 0;

    /** The return code that represents that the requested point is not in the curve */
    int NOT_IN_CURVE = -4;

    /**
     * Creates a GroupElement byte internal representation from a seed byte array
     * @param group on which of the groups of the curve to perform the operation
     * @param input a byte array that will be used as seed to get the random point
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int groupElementsFromSeed(final int group, final byte[] input, final byte[] output);

    /**
     * Attempts to obtain a GroupElement byte internal representation from a given hashed value
     *
     * @param group  on which of the groups of the curve to perform the operation
     * @param input  a byte array of that represents an x coordinate
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, {@link GroupElementsLibraryAdapter#NOT_IN_CURVE}
     * if the point is not in the curve, or a less than zero error code if there was an error
     */
    int groupElementsHashToGroup(final int group, final byte[] input, final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the point at infinity
     * @param group on which of the groups of the curve to perform the operation
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int groupElementsZero(final int group, final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the generator point of the group
     * @param group on which of the groups of the curve to perform the operation
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int groupElementsGenerator(final int group, final byte[] output);

    /**
     * returns if two representations are the same
     *
     * @param group on which of the groups of the curve to perform the operation
     * @param value a byte array representation of the point argument
     * @param other a byte array representation of the point argument
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    int groupElementsEquals(final int group, final byte[] value, final byte[] other);

    /**
     * Returns the byte size of a groupElement internal representation.
     *
     * @param group on which of the groups of the curve to perform the operation
     * @return the byte size of a groupElement internal representation.
     */
    int groupElementsSize(final int group);

    /**
     * Returns the addition of code {@code value} and  {@code other}.
     *
     * @param group on which of the groups of the curve to perform the operation
     * @param value a byte array representation of the point argument
     * @param other a byte array representation of the point argument
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int groupElementsAdd(final int group, final byte[] value, final byte[] other, final byte[] output);

    /**
     * Returns the scalar multiplication between code {@code point} and {@code scalar}.
     *
     * @param group on which of the groups of the curve to perform the operation
     * @param point a byte array representation of the point argument
     * @param scalar the byte array representation of the scalar
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int groupElementsScalarMul(final int group, final byte[] point, final byte[] scalar, final byte[] output);

    /**
     * Returns the scalar multiplication between code {@code point} and {@code scalar}.
     *
     * @param group on which of the groups of the curve to perform the operation
     * @param point a byte array that holds the internal representation of the point argument
     * @param scalar a long representation of the scalar
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int groupElementsLongMul(final int group, final byte[] point, final long scalar, final byte[] output);

    /**
     * Returns the internal representation of a point under different modes.
     *
     * @param group on which of the groups of the curve to perform the operation
     * @param isCompressed if the input byte array is in compressed format
     * @param validate if the point should be validated when created
     * @param compress if the output byte array should be in compressed format
     * @param input a byte array of that holds the coordinates of the point
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, {@link GroupElementsLibraryAdapter#NOT_IN_CURVE}
     * if the point is invalid or a less than zero error code if there was an error
     */
    int groupElementsBytes(
            final int group,
            final boolean isCompressed,
            final boolean validate,
            final boolean compress,
            final byte[] input,
            final byte[] output);

    /**
     * Returns the result of the multiplication of each point in the  {@code points} list with each scalar in the {@code scalars} list.
     *
     * @param group   on which of the groups of the curve to perform the operation
     * @param scalars a byte matrix representing a list of N byte arrays each representing a scalar
     * @param points a byte matrix representing a list of N byte arrays each representing a point
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an
     * error
     */
    int groupElementsMsm(final int group, final byte[][] scalars, final byte[][] points, final byte[] output);

    /**
     * Returns the result of the multiplication of each point in the  {@code points} list with each scalar in the {@code scalars} list.
     *
     * @param group   on which of the groups of the curve to perform the operation
     * @param scalars an int array representing a list of N scalars
     * @param points a byte matrix representing a list of N point
     * @param output a byte array representation of the point resulting of this operation
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an
     * error
     */
    int groupElementsMsm(final int group, final long[] scalars, final byte[][] points, final byte[] output);

    /**
     * Returns the point that is the result of the total sum a collection of points
     *
     * @param group on which of the groups of the curve to perform the operation
     * @param input a byte matrix representing a list of N byte arrays representing each point
     * @param output an array to hold the internal representation of the point
     * @return {@link GroupElementsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    int groupElementsBatchAdd(final int group, final byte[][] input, final byte[] output);
}
