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
import com.hedera.cryptography.altbn128.adapter.FieldsLibraryAdapter;
import com.hedera.cryptography.altbn128.adapter.Group2LibraryAdapter;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This class serves as an adapter between the Java code and the native arkworks altBn128 Rust functions.
 **/
public final class ArkBn254Adapter implements FieldsLibraryAdapter, Group2LibraryAdapter {

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
     * @param inputSeed the byte seed to be used to create the new scalar
     * @param output    the byte array that will be filled with the new scalar
     * @return {@link FieldsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromRandomSeed(final byte[] inputSeed, final byte[] output);

    /**
     * Creates a new scalar from a long
     *
     * @param inputLong the long to be used to create the new scalar
     * @param output    the byte array that will be filled with the new scalar
     * @return {@link FieldsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromLong(final long inputLong, final byte[] output);

    /**
     * Creates a new scalar from a byte[]
     *
     * @param input  the that represents the scalar
     * @param output the byte array that will be filled with the new scalar
     * @return {@link FieldsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsFromBytes(final byte[] input, final byte[] output);

    /**
     * Creates a new zero value scalar
     *
     * @param output the byte array that will be filled with the new scalar
     * @return {@link FieldsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int fieldElementsZero(final byte[] output);

    /**
     * Creates a new one value scalar.
     *
     * @param output the byte array that will be filled with the new scalar
     * @return {@link FieldsLibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
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
    public native int g2FromCoordinates(final byte[] x1, final byte[] x2, final byte[] y1, final byte[] y2, final byte[] output);

    /**
     * Creates a GroupElement byte internal representation from a seed byte array
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param input a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int g2FromSeed(final byte[] input, final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the point at infinity
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int g2Zero(final byte[] output);

    /**
     * Returns the GroupElement byte internal representation of the generator point of the group
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int g2Generator(final byte[] output);

    /**
     * returns if two representations are the same
     *@implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param value a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param other a byte array of {@link Group2LibraryAdapter#g2Size()}  that contains the internal represents the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int g2Equals(final byte[] value, final byte[] other);

    /**
     * Returns the byte size of a groupElement internal representation.
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int g2Size();

    /**
     * Returns the byte size of a groupElement affine representation.
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int g2AffineSize();

    /**
     * Returns the byte size of the expected seed byte array for creating random points on the curve.
     *
     * @return a non-zero error code if there was an error, otherwise 0
     */
    public native int g2RandomSeedSize();

    /**
     * panic function invocation
     * TODO: remove
     * @return nothing this function panics
     */
    public native int panicTest();

    /**
     * Returns the addition of code {@code value} and  {@code other}.
     *
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param value a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param other a byte array of {@link Group2LibraryAdapter#g2Size()} that contains the internal represents the point
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int g2Add(final byte[] value, final byte[] other, final byte[] output);

    /**
     * Returns the scalar multiplication between code {@code point} and {@code scalar}.
     *
     *@implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param point a byte array of {@link Group2LibraryAdapter#g2Size()} that will be used as the seed to create the point
     * @param scalar a byte array of {@link FieldsLibraryAdapter#fieldElementsSize()}} that contains the representation of the scalar
     * @param output a {@link Group2LibraryAdapter#g2Size()} array to hold the internal representation of the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int g2ScalarMul(final byte[] point, final byte[] scalar, final byte[] output);

    /**
     * Returns the serialization of the affine representation of the point
     *
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param point a byte array of {@link Group2LibraryAdapter#g2Size()} that will be used as the seed to create the point
     * @param output a {@link Group2LibraryAdapter#g2AffineSize()} array to hold the internal representation of the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int g2ToAdHocAffineSerialization(final byte[] point, final byte[] output);

    /**
     * Returns the serialization of the affine representation of the point
     *
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param point a byte array of {@link Group2LibraryAdapter#g2Size()} that will be used as the seed to create the point
     * @param output a {@link Group2LibraryAdapter#g2AffineSize()} array to hold the internal representation of the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int g2ToAffineSerialization(final byte[] point, final byte[] output);

    /**
     * Returns the result of the multiplication of the {@link Group2LibraryAdapter#g2Generator(byte[])} for each scalar in the {@code scalars} list
     *
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param scalars a byte matrix representing a list of N byte arrays of {@link FieldsLibraryAdapter#fieldElementsSize()}} size each representing a scalar
     * @param outputs a byte matrix of N byte arrays {@link Group2LibraryAdapter#g2AffineSize()} size to hold the internal representation of the generator point times the scalar in {@code scalars}
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int g2batchScalarMultiplication(final byte[][] scalars, final byte[][] outputs);

    /**
     * Returns the point that is the result of the total sum a collection of points
     *
     * @implNote inputs and outputs are not validated for nullity or correct sizing. Callers needs to handle that.
     * @param input a byte matrix representing a list of N byte arrays of {@link Group2LibraryAdapter#g2Size()} representing each point
     * @param output a {@link Group2LibraryAdapter#g2AffineSize()} array to hold the internal representation of the point
     * @return 0 if false, 1 if true, or a less than zero error code if there was an error
     */
    public native int g2batchAdd(final byte[][] input, final byte[] output);

    /**
     * Creates a GroupElement byte internal representation from an external affine representation of {@link Group2LibraryAdapter#g2AffineSize()} bytes long.
     *
     * @param input  a {@link Group2LibraryAdapter#g2AffineSize()} size array  affine representation of bytes long
     * @param output a {@link Group2LibraryAdapter#g2Size()} size array to hold the internal representation of the point
     * @return {@link Group2LibraryAdapter#SUCCESS} for success, or a less than zero error code if there was an error
     */
    public native int g2FromAffine(final byte[] input, final byte[] output) ;
}
