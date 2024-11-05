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

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * A Threshold Signature Scheme Service.
 * <p>
 * Contract of TSS:
 *   <ul>
 *       <li>Get a {@link TssServiceGenesisStage}</li>
 *       <li>Get a {@link TssServiceRekeyStage}</li>
 *   </ul>
 */
public interface TssService {

    /**
     * Returns the genesis stage.
     * In this stage all participants collaborate to discover a shared polynomial.
     * Threshold Signature Scheme dependant operations
     * <p>
     * Contract of {@link TssServiceGenesisStage} stage:
     * <ul>
     *     <li>Generate {@link TssMessage} out of a random share</li>
     *     <li>Verify {@link TssMessage} out of a {@link TssParticipantDirectory}</li>
     *     <li>Obtain the list of {@link TssPrivateShare} out of a {@link TssParticipantDirectory}</li>
     *     <li>Obtain the list of {@link TssPublicShare} out of a {@link TssParticipantDirectory}</li>
     * </ul>
     * @return the genesis stage.
     */
    TssServiceGenesisStage genesisStage();

    /**
     * Returns the rekey stage.
     * In this stage all participants recover keys belonging to an already established polynomial.
     *
     * @return the rekey stage.
     */
    TssServiceRekeyStage rekeyStage();

    /**
     * Creates a {@link TssMessage} of a byte array representation.
     * @see TssMessage#bytes() for the specification that message needs to follow.
     * @param message message the byte representation of the opaque underlying structure used by the library
     * @return a TssMessage instance
     */
    @NonNull
    TssMessage messageFromBytes(@NonNull byte[] message);
}
