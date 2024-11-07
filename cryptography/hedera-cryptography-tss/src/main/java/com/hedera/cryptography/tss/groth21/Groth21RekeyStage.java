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

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssServiceRekeyStage;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Random;

/**
 *  The rekey stage of Groth21 based TssService implementation.
 *  In this stage, the {@link TssMessage} is based on previous material
 *  The aggregation rules for {@link TssPrivateShare} and {@link TssPrivateShare} follows {@link com.hedera.cryptography.tss.extensions.Lagrange} interpolation.
 * @see TssServiceRekeyStage
 */
public class Groth21RekeyStage extends Groth21Stage implements TssServiceRekeyStage {

    /**
     * Constructor
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     * @param random a source of randomness
     */
    public Groth21RekeyStage(@NonNull final SignatureSchema signatureSchema, @NonNull final Random random) {
        super(signatureSchema, random);
    }

    @NonNull
    @Override
    public List<TssPrivateShare> obtainPrivateShares(
            @NonNull final TssParticipantDirectory participantDirectory,
            @NonNull final List<TssMessage> validTssMessages) {
        throw new UnsupportedOperationException("Unsupported operation");
    }

    @NonNull
    @Override
    public List<TssPublicShare> obtainPublicShares(
            @NonNull final TssParticipantDirectory participantDirectory,
            @NonNull final List<TssMessage> validTssMessages) {
        throw new UnsupportedOperationException("Unsupported operation");
    }
}
