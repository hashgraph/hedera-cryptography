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

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.tss.extensions.serialization.TssMessageSerializers;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;

/**
 * A message sent as part of either genesis keying, or rekeying.
 */
public interface TssMessage {

    /**
     * Current supported version.
     * All messages using a different version will throw an error when parsed.
     */
    int MESSAGE_CURRENT_VERSION = 0;

    /**
     * Do not use.
     * @return a byte array representing this instance.
     * @deprecated Use {@link TssMessageSerializers}
     */
    @Deprecated
    byte[] toBytes();

    /**
     * Return the share id that generated this message
     * @return the share id that generated this message
     */
    @NonNull
    Integer generatingShare();

    /**
     * Returns the ElGamal shared randomness.
     * @return the ElGamal shared randomness list
     */
    @NonNull
    List<GroupElement> sharedRandomness();

    /**
     * Returns the ElGamal cipher-texts
     * @return the ElGamal cipher-texts
     */
    @NonNull
    List<List<GroupElement>> shareCiphertexts();

    /**
     * Returns the feldman commitments.
     * @return the Feldman's commitments
     */
    @NonNull
    List<GroupElement> polynomialCommitments();

    /**
     * Returns the f component of the proof.
     * @return the f component of the proof.
     */
    @NonNull
    GroupElement f();

    /**
     * Returns the a component of the proof.
     * @return the a component of the proof.
     */
    @NonNull
    GroupElement a();

    /**
     * Returns the y component of the proof.
     * @return the y component of the proof.
     */
    @NonNull
    GroupElement y();

    /**
     * Return the zr component of the proof.
     * @return the zr component of the proof.
     */
    @NonNull
    FieldElement zR();

    /**
     * Return the zA component of the proof.
     * @return the zA component of the proof.
     */
    @NonNull
    FieldElement zA();
}
