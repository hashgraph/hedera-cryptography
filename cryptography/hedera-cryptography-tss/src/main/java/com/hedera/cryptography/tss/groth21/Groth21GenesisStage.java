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

package com.hedera.cryptography.tss.groth21;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssServiceGenesisStage;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Random;

/**
 *  The genesis stage of Groth21 based TssService implementation.
 *  In this stage, given the lack of previous material, the generations of {@link TssMessage} is based on random information,
 *  and the aggregation rules for {@link TssPrivateShare} and {@link TssPrivateShare} follows bls addition.
 * @see TssServiceGenesisStage
 */
public class Groth21GenesisStage extends Groth21Stage implements TssServiceGenesisStage {

    /**
     * Constructor
     * @param signatureSchema Defines which and how elliptic curve is used in the protocol
     * @param random a source of randomness
     */
    public Groth21GenesisStage(@NonNull final SignatureSchema signatureSchema, @NonNull final Random random) {
        super(signatureSchema, random);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifyTssMessage(
            @NonNull final TssParticipantDirectory tssTargetParticipantDirectory,
            @NonNull final TssMessage tssMessage) {
        return super.verifyTssMessage(tssTargetParticipantDirectory, null, tssMessage);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public TssMessage generateTssMessage(@NonNull final TssParticipantDirectory tssGenesisParticipantDirectory) {
        final int tssShareId = tssGenesisParticipantDirectory.getParticipantId() + 1;
        final TssPrivateShare randomTssPrivateShare =
                new TssPrivateShare(tssShareId, BlsPrivateKey.create(signatureSchema, random));
        return generateTssMessage(tssGenesisParticipantDirectory, randomTssPrivateShare);
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public List<TssPrivateShare> obtainPrivateShares(
            @NonNull final TssParticipantDirectory participantDirectory,
            @NonNull final List<TssMessage> validTssMessages) {
        throw new UnsupportedOperationException("Unsupported operation");
    }

    /**
     * {@inheritDoc}
     */
    @NonNull
    @Override
    public List<TssPublicShare> obtainPublicShares(
            @NonNull final TssParticipantDirectory participantDirectory,
            @NonNull final List<TssMessage> validTssMessages) {
        throw new UnsupportedOperationException("Unsupported operation");
    }
}
