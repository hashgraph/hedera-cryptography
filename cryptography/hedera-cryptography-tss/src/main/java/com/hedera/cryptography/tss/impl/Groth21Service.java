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

package com.hedera.cryptography.tss.impl;

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssMessageParsingException;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssServiceGenesisStage;
import com.hedera.cryptography.tss.api.TssServiceRekeyStage;
import com.hedera.cryptography.tss.extensions.serialization.DefaultTssMessageSerialization;
import com.hedera.cryptography.tss.impl.groth21.Groth21GenesisStage;
import com.hedera.cryptography.tss.impl.groth21.Groth21RekeyStage;
import com.hedera.cryptography.utils.serialization.Transformer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Random;

/**
 * A Threshold Signature Scheme (TSS) Service based on Groth21.
 * Use the service to:
 *   <ul>
 *       <li>Get a {@link Groth21GenesisStage}</li>
 *       <li>Get a {@link Groth21RekeyStage}</li>
 *   </ul>
 */
public class Groth21Service implements TssService {
    private final SignatureSchema signatureSchema;
    private final Groth21GenesisStage genesisStage;
    private final Groth21RekeyStage rekeyStage;

    /**
     * Constructor
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @param random a source of randomness
     */
    public Groth21Service(final @NonNull SignatureSchema signatureSchema, final @NonNull Random random) {
        this.signatureSchema = signatureSchema;
        this.genesisStage = new Groth21GenesisStage(signatureSchema, random);
        this.rekeyStage = new Groth21RekeyStage(signatureSchema, random);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TssServiceGenesisStage genesisStage() {
        return genesisStage;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TssServiceRekeyStage rekeyStage() {
        return rekeyStage;
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Deprecated
    @Override
    public TssMessage messageFromBytes(
            @NonNull final TssParticipantDirectory tssParticipantDirectory, @NonNull final byte[] message)
            throws TssMessageParsingException {
        return this.messageFrom(
                DefaultTssMessageSerialization.getDeserializer(signatureSchema, tssParticipantDirectory), message);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public <S> TssMessage messageFrom(
            @NonNull final Transformer<S, TssMessage> tssMessageTransformer, @NonNull final S message)
            throws TssMessageParsingException {
        try {
            return tssMessageTransformer.transform(message);
        } catch (Exception e) {
            throw new TssMessageParsingException("There was an error interpreting the TssMessage", e);
        }
    }
}
