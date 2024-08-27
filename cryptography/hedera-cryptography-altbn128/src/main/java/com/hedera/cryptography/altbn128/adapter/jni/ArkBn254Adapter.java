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

package com.hedera.cryptography.altbn128.adapter.jni;

import com.hedera.common.nativesupport.SingletonLoader;
import com.hedera.cryptography.altbn128.adapter.LibraryAdapter;

/**
 * This class serves as an adapter between the Java code and the native arkworks altBn128 Rust functions.
 **/
public final class ArkBn254Adapter implements LibraryAdapter {
    /**
     * Instance Holder for lazy loading
     */
    private static final SingletonLoader<ArkBn254Adapter> INSTANCE_HOLDER =
            new SingletonLoader<>("libbn254", new ArkBn254Adapter());

    private ArkBn254Adapter() {}

    /**
     * @return the singleton instance of this library adapter.
     */
    public static ArkBn254Adapter getInstance() {
        return INSTANCE_HOLDER.getInstance();
    }

    /**
     * Creates a new random scalar from a seed value
     *
     * @param inputSeed the byte seed to be used to create the new scalar
     * @param output    the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromRandomSeed(final byte[] inputSeed, final byte[] output);

    /**
     * Creates a new scalar from a long
     *
     * @param inputLong the long to be used to create the new scalar
     * @param output    the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromLong(final long inputLong, final byte[] output);

    /**
     * Creates a new scalar from a byte[]
     *
     * @param input  the that represents the scalar
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromBytes(final byte[] input, final byte[] output);

    /**
     * Creates a new zero value scalar
     *
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsZero(final byte[] output);

    /**
     * Creates a new one value scalar.
     *
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsOne(final byte[] output);

    /**
     * returns if two representations are the same
     *
     * @param value the that represents a scalar
     * @param other the that represents another scalar
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int fieldElementsEquals(final byte[] value, final byte[] other);

    /**
     * Returns the byte size of a field element object.
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementsSize();

    /**
     * Returns the byte size of the random seed to use.
     *
     * @return the byte size of the random seed to use.
     */
    public native int fieldElementsRandomSeedSize();
}
