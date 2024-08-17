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
import com.hedera.cryptography.altbn128.AltBn128Exception;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Class containing definitions for native rust functions
 **/
public final class AltBn128FieldElements {

    public static final int SIZE = 48;
    public static final int SEED_SIZE = 32;


    static class InstanceHolder {
        public static final AltBn128FieldElements INSTANCE = new AltBn128FieldElements().initialize();
    }

    private static final AtomicBoolean PENDING_INITIALIZATION = new AtomicBoolean(true);

    public static AltBn128FieldElements getInstance() {
        return InstanceHolder.INSTANCE;
    }

    /**
     * Initializes the class by loading the necessary native libraries.
     *
     * @return this instance.
     */
    @NonNull
    public AltBn128FieldElements initialize() {
        if (PENDING_INITIALIZATION.get()) {
            synchronized (this) {
                if (!PENDING_INITIALIZATION.get()) {
                    return this;
                }
                final NativeLibrary library = NativeLibrary.withName("altbn128-fieldElements");
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
    public static final int FALSE = -1;

    /** Hidden constructor */
    private AltBn128FieldElements() {}

    /**
     * Creates a new random scalar from a seed value
     *
     * @param inputSeed the byte seed to be used to create the new scalar
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    private native int fieldElementsFromRandomSeed(final byte[] inputSeed, final byte[] output);

    /**
     * Creates a new scalar from a long
     *
     * @param inputLong the long to be used to create the new scalar
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    private native int fieldElementsFromLong(final long inputLong, final byte[] output);

    /**
     * Determines if the input representation is a valida FieldElement
     *
     * @param input the that represents the scalar
     * @return 0 if the input is a valid scalar representation, otherwise -1 if it is not or other non-zero error code if there was an error,
     */
    public native int fieldElementsIsValid(final byte[] input);


    /**
     * Creates a new zero value scalar
     *
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementsZero(final byte[] output);

    /**
     * Creates a new one value scalar.
     *
     * @param output the byte array that will be filled with the new scalar
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementsOne(final byte[] output);

    /**
     * Returns the byte size of a field element object.
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int fieldElementSize();


    public byte[] fieldElementsFromLong(final long inputLong){
        final ByteBuffer bb = ByteBuffer.allocate(SIZE);
        final int result = fieldElementsFromLong(inputLong, bb.array());
        if(result != SUCCESS){
            throw new AltBn128Exception(result, "fieldElementFromLong", this.getClass());
        }
        return bb.array();
    }


    public byte[] fieldElementsFromRandomSeed(@NonNull final byte[] seed) {
        if (Objects.requireNonNull(seed, "Seed must not be null").length != SEED_SIZE) {
            throw new IllegalArgumentException("Seed must be " + SEED_SIZE + " bytes");
        }
        final ByteBuffer bb = ByteBuffer.allocate(SIZE);
        final int result = fieldElementsFromRandomSeed(seed, bb.array());
        if(result != SUCCESS){
            throw new AltBn128Exception(result, "fieldElementFromRandomSeed", this.getClass());
        }
        return bb.array();
    }

    public byte[] fieldElementsFromBytes(@NonNull final byte[] representation) {
        if (Objects.requireNonNull(representation, "representation must not be null").length != SIZE) {
            throw new IllegalArgumentException("Representation must be " + SIZE + " bytes");
        }
        final int result = fieldElementsIsValid(representation);
        if(result == FALSE){
            throw new IllegalArgumentException( "Not a valid scalar representation" );
        }
        if (result != SUCCESS) {
            throw new AltBn128Exception(result, "fieldElementFromBytes", this.getClass());
        }
        return representation;
    }
}
