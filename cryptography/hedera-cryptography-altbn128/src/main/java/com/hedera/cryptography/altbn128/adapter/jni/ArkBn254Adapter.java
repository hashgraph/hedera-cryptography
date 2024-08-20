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

import com.hedera.common.nativesupport.NativeLibrary;
import com.hedera.cryptography.altbn128.adapter.LibraryAdapter;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This class serves as an adapter between the Java code and the native arkworks altBn128 Rust functions.
 **/
public final class ArkBn254Adapter implements LibraryAdapter {

    /**
     * Instance Holder for lazy loading
     */
    static class InstanceHolder {
        /**
         * The Singleton instance
         */
        public static final ArkBn254Adapter INSTANCE = new ArkBn254Adapter().initialize();
    }

    /**
     * True by default, false after initialization.
     */
    private static final AtomicBoolean PENDING_INITIALIZATION = new AtomicBoolean(true);

    /**
     * Returns the singleton instance of this library adapter.
     * @return the singleton instance of this library adapter.
     */
    public static ArkBn254Adapter getInstance() {
        return InstanceHolder.INSTANCE;
    }

    /**
     * Initializes the class by loading the necessary native libraries.
     *
     * @return this instance.
     */
    @NonNull
    public ArkBn254Adapter initialize() {
        if (PENDING_INITIALIZATION.get()) {
            synchronized (this) {
                if (!PENDING_INITIALIZATION.get()) {
                    return this;
                }
                final NativeLibrary library = NativeLibrary.withName("libbn254");
                try {
                    // JPMS does not allow for resources contained in a module to be loaded in a separated class
                    // So we are forced to load this the InputStream in a class stored in a jar that holds the resource
                    final InputStream is = this.getClass().getModule().getResourceAsStream(library.locationInJar());
                    if (is == null) {
                        throw new UncheckedIOException(new IOException("Could not find " + library.name()));
                    }
                    library.install(is);
                } catch (IOException e) {
                    throw new UncheckedIOException("Unable to load adapter " + library.name(), new IOException(e));
                }
                PENDING_INITIALIZATION.set(false);
            }
        }
        return this;
    }

    /**
     * Creates a new random scalar from a seed value
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param inputSeed       the byte seed to be used to create the new scalar
     * @param output          the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromRandomSeed(
            final int groupAssignment, final byte[] inputSeed, final byte[] output);

    /**
     * Creates a new scalar from a long
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param inputLong       the long to be used to create the new scalar
     * @param output          the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromLong(final int groupAssignment, final long inputLong, final byte[] output);

    /**
     * Creates a new scalar from a byte[]
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param input           the that represents the scalar
     * @param output          the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromBytes(final int groupAssignment, final byte[] input, final byte[] output);

    /**
     * Creates a new zero value scalar
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsZero(final int groupAssignment, final byte[] output);

    /**
     * Creates a new one value scalar.
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param output the byte array that will be filled with the new scalar
     * @return {@link LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsOne(final int groupAssignment, final byte[] output);

    /**
     * returns if two representations are the same
     *
     * @param groupAssignment An int representing the ordinal for selecting the elliptic curve group to use.
     * @param value           the that represents a scalar
     * @param other          the that represents another scalar
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int fieldElementsEquals(final int groupAssignment, final byte[] value, final byte[] other);
}
