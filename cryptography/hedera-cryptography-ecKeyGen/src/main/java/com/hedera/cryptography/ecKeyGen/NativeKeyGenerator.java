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

package com.hedera.cryptography.ecKeyGen;

import com.hedera.common.nativesupport.NativeLibrary;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * An implementation of {@link KeyGenerator} that uses JNI and rust code to generate the keys
 */
public class NativeKeyGenerator implements KeyGenerator {
    private static final AtomicBoolean IS_INITIALIZED = new AtomicBoolean(false);

    /**
     * Initializes the class by loading the necessary native libraries.
     *
     * @return this instance.
     */
    public NativeKeyGenerator initialize() {
        if (IS_INITIALIZED.compareAndSet(false, true)) {
            final NativeLibrary library = NativeLibrary.withName("libkey_gen");
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
        }
        return this;
    }

    /**
     * JNI function to generate a key pair (private key and public key) and return them as Java strings.
     *
     * @param groupAssignment  An int representing the {@link GroupAssignment} ordinal for selecting the elliptic curve group to use.
     * @param out  A Java object array of size 2 to store the resulting private key and public key.
     * @return an integer status code (0 for success, -1 for failure).
     */
    public native int generateKeyPair(final int groupAssignment, byte[][] out);
    /**
     * JNI function to generate a public key given an existent private key and return it as Java strings.
     *
     * @param groupAssignment  An int representing the {@link GroupAssignment} ordinal for selecting the elliptic curve group to use.
     * @param sk  A Java object array representing the private key.
     * @return A Java object array representing the public key
     */
    public native byte[] generatePublicKey(final int groupAssignment, final byte[] sk);
}
