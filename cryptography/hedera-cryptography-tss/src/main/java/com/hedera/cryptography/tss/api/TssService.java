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

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.impl.Groth21Service;
import com.hedera.cryptography.tss.impl.groth21.Groth21GenesisStage;
import com.hedera.cryptography.tss.impl.groth21.Groth21RekeyStage;
import com.hedera.cryptography.utils.serialization.Transformer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Random;

/**
 * A Threshold Signature Scheme Service.
 * <p>
 * Contract of TssService:
 *   <ul>
 *       <li>Get a {@link TssServiceGenesisStage}: Returns the genesis stage</li>
 *       <li>Get a {@link TssServiceRekeyStage}: Returns the rekey stage.</li>
 *   </ul>
 */
public interface TssService {

    /**
     * In this stage all participants collaborate to discover a shared polynomial.
     * <p>
     * Contract of {@link TssServiceGenesisStage} stage:
     * <ul>
     *     <li>Generate {@link TssMessage} from a random share</li>
     *     <li>Verify {@link TssMessage} with a {@link TssParticipantDirectory}</li>
     *     <li>Obtain the list of {@link TssPrivateShare} with a {@link TssParticipantDirectory}</li>
     *     <li>Obtain the list of {@link TssPublicShare} with a {@link TssParticipantDirectory}</li>
     * </ul>
     * @return the genesis stage.
     */
    @NonNull
    TssServiceGenesisStage genesisStage();

    /**
     * In this stage all participants recover keys belonging to an already established polynomial.
     *  Contract of {@link TssServiceRekeyStage} stage:
     * <ul>
     *     <li>Generate {@link TssMessage} from a {@link TssPrivateShare}</li>
     *     <li>Verify {@link TssMessage} with a {@link TssParticipantDirectory},
     *        and all previous {@link TssPublicShare}</li>
     *     <li>Obtain the list of {@link TssPrivateShare} with a {@link TssParticipantDirectory}</li>
     *     <li>Obtain the list of {@link TssPublicShare} with a {@link TssParticipantDirectory}</li>
     * </ul>
     *
     * @return the rekey stage.
     */
    @NonNull
    TssServiceRekeyStage rekeyStage();

    /**
     * Deserializes a {@link TssMessage} from a byte array representation using the provided deserializer.
     * @param tssParticipantDirectory the candidate tss directory
     * @param message the message being transformed
     * @throws TssMessageParsingException in case of error while parsing the TssMessage from its byte array format
     * @return a TssMessage instance
     * @deprecated use an instance of {@link com.hedera.cryptography.utils.serialization.Deserializer}
     *  or {@link TssService#messageFrom(Transformer, Object)}
     */
    @NonNull
    @Deprecated
    TssMessage messageFromBytes(@NonNull TssParticipantDirectory tssParticipantDirectory, @NonNull byte[] message)
            throws TssMessageParsingException;

    /**
     * Gets a {@link TssMessage} from a source object using the provided transformer.
     * @param <S> source type
     * @param tssMessageTransformer a transformer instance to use.
     * @param message the message being transformed
     * @return a TssMessage instance
     * @throws TssMessageParsingException in case of error while parsing the TssMessage from its byte array format
     */
    @NonNull
    <S> TssMessage messageFrom(@NonNull Transformer<S, TssMessage> tssMessageTransformer, @NonNull S message)
            throws TssMessageParsingException;

    /**
     * Gets a Threshold Signature Scheme (TSS) Service Instance.
     * Use the service to:
     *   <ul>
     *       <li>Get a {@link Groth21GenesisStage}</li>
     *       <li>Get a {@link Groth21RekeyStage}</li>
     *   </ul>
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @param random a source of randomness
     * @return the default provided implementation of a TssService
     */
    @NonNull
    static TssService createDefaultService(@NonNull final SignatureSchema signatureSchema,@NonNull final Random random) {
        return new Groth21Service(signatureSchema, random);
    }
}
