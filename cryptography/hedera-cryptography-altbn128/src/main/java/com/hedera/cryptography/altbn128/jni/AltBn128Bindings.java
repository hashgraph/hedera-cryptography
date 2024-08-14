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

package com.hedera.cryptography.altbn128.jni;

import com.hedera.common.nativesupport.NativeLibrary;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Class containing definitions for native rust functions
 **/
public final class AltBn128Bindings {

    static class InstanceHolder {
        public static final AltBn128Bindings INSTANCE = new AltBn128Bindings().initialize();
    }

    private static final AtomicBoolean PENDING_INITIALIZATION = new AtomicBoolean(true);

    public static AltBn128Bindings getInstance() {
        return InstanceHolder.INSTANCE;
    }

    /**
     * Initializes the class by loading the necessary native libraries.
     *
     * @return this instance.
     */
    @NonNull
    public AltBn128Bindings initialize() {
        if (PENDING_INITIALIZATION.get()) {
            synchronized (this) {
                if (!PENDING_INITIALIZATION.get()) {
                    return this;
                }
                final NativeLibrary library = NativeLibrary.withName("altbn128");
                try {
                    // JPMS does not allow for resources contained in a module to be loaded in a separated class
                    // So we are forced to load this the InputStream in a class stored in a jar that holds the resource
                    final InputStream is = this.getClass().getModule().getResourceAsStream(library.locationInJar());
                    if (is == null) {
                        throw new UncheckedIOException(new IOException("Could not find " + library.name()));
                    }
                    library.install(is);
                } catch (IOException e) {
                    throw new UncheckedIOException("Unable to load library " + library.name(), new IOException(e));
                }
                PENDING_INITIALIZATION.set(false);
            }
        }
        return this;
    }

    /** The code returned from the rust interface if a call succeeds */
    public static final int SUCCESS = 0;

    /** Hidden constructor */
    public AltBn128Bindings() {}

    /**
     * Creates a new random scalar from a seed value
     *
     * @param inputSeed the byte seed to be used to create the new scalar
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementFromRandomSeed(final byte[] inputSeed, final byte[] output);

    /**
     * Creates a new scalar from a long
     *
     * @param inputLong the long to be used to create the new scalar
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementFromLong(final long inputLong, final byte[] output);

    /**
     * Creates a new zero value scalar
     *
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementZero(final byte[] output);

    /**
     * Creates a new one value scalar
     *
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementOne(final byte[] output);

    /**
     * Rerturns the byte size of a field element object
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementSize();
}
