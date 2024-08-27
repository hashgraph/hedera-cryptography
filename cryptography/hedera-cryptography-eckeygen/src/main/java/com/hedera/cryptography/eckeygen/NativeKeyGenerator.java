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

package com.hedera.cryptography.eckeygen;

import com.hedera.common.nativesupport.SingletonLoader;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * An implementation of {@link KeyGenerator} that uses JNI and rust code to generate the keys
 */
public class NativeKeyGenerator implements KeyGenerator {
    private static final SingletonLoader<NativeKeyGenerator> INSTANCE_HOLDER =
            new SingletonLoader<>("libkey_gen", new NativeKeyGenerator());

    private NativeKeyGenerator() {}

    public static NativeKeyGenerator getInstance() {
        return INSTANCE_HOLDER.getInstance();
    }

    /**
     * JNI function to generate a key pair (private key and public key) and return them as byte arrays.
     * Index 0 corresponds to the private key.
     * Index 1 corresponds to the public key.
     *
     * @param groupAssignment  An int representing the {@link GroupAssignment} ordinal for selecting the elliptic curve group to use.
     * @return A byte array of size 2 with private key and public key each as byte[].
     */
    @Nullable
    public native byte[][] generateKeyPair(final int groupAssignment);
    /**
     * JNI function to generate a public key given an existent private key and return it as byte array.
     *
     * @param groupAssignment  An int representing the {@link GroupAssignment} ordinal for selecting the elliptic curve group to use.
     * @param sk A Java byte[] array representing the private key.
     * @return A Java byte[] array representing the public key
     */
    @Nullable
    public native byte[] generatePublicKey(final int groupAssignment, @NonNull final byte[] sk);
}
