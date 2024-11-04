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

package com.hedera.cryptography.tss.api;

import static java.util.Objects.requireNonNull;

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.tss.groth21.Groth21Message;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A message sent as part of either genesis keying, or rekeying.
 */
public interface TssMessage {

    /**
     * Specification of the format:
     * Given {@code e}: {@link FieldElement#size()} of the chosen curve
     * and {@code g}: {@link GroupElement#size()} of the defined
     * {@link SignatureSchema#getPublicKeyGroup()}
     * A TssMessage will consist of:
     * <ul>
     *  <li>4 fixed bytes representing the version of the message
     *  <li>1 byte representing the SignatureSchema that originated the message
     *  <li>4 fixed bytes representing the shareId that originated the message
     *  <li>4 fixed bytes representing the size N_1 of the next list
     *  <li>(total of N_1*g bytes) a list of N_1 elements of g size representing the shared randomness
     *  <li>4 fixed bytes representing the size M of the next lists
     *  <li>(total of M*N_2*g)
     *  (0 to M):
     *  <ul>
     *       <li>4 bytes representing the size N_2 of the next list
     *       <li>(total of N_2*g bytes) a list of N_2 elements of g size representing the encrypted shares
     *      </ul>
     *  <li>4 fixed bytes representing the size N_3 of the next list
     *  <li>(total of N_3*g bytes) a list of N_3 elements of g size representing the polynomial commitment
     *  <li>g bytes representing the proof f element
     *  <li>g bytes representing the proof a element
     *  <li>s bytes representing the proof zr element
     *  <li>s bytes representing the proof za element
     *  </ul>
     * @return the byte representation of a TssMessage
     */
    byte[] bytes();

    /**
     * Creates a byte array out of a byte array representation.
     * @see TssMessage#bytes() for the specification followed
     * @param bytes bytes the byte representation of the opaque underlying structure used by the library
     * @return a TssMessage instance
     */
    @NonNull
    static TssMessage fromBytes(@NonNull byte[] bytes) {
        requireNonNull(bytes, "bytes must not be null");
        return new Groth21Message(bytes);
    }
}
