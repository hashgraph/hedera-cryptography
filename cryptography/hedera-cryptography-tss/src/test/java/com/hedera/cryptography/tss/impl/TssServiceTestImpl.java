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

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssServiceGenesisStage;
import com.hedera.cryptography.tss.api.TssServiceRekeyStage;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * A prototype implementation of the TssService.
 * future-work:Complete this implementation.
 */
public class TssServiceTestImpl implements TssService {
    private final SignatureSchema signatureSchema;

    /**
     * Generates a new instance of this prototype implementation.
     *
     * @param signatureSchema the predefined parameters that define the curve and group selection
     * @param random the RNG
     */
    public TssServiceTestImpl(@NonNull final SignatureSchema signatureSchema, @NonNull final Random random) {
        this.signatureSchema = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
    }

    @Override
    public TssServiceGenesisStage genesisStage() {
        return new TssServiceGenesisStage() {
            @NonNull
            @Override
            public TssMessage generateTssMessage(@NonNull final TssParticipantDirectory tssParticipantDirectory) {
                return () -> new byte[0];
            }

            @Override
            public boolean verifyTssMessage(
                    @NonNull final TssParticipantDirectory participantDirectory, @NonNull final TssMessage tssMessage) {
                return true;
            }

            @NonNull
            @Override
            public TssMessage generateTssMessage(
                    @NonNull final TssParticipantDirectory tssParticipantDirectory,
                    @NonNull final TssPrivateShare privateShare) {
                return () -> new byte[0];
            }

            @NonNull
            @Override
            public List<TssPrivateShare> obtainPrivateShares(
                    @NonNull final TssParticipantDirectory participantDirectory,
                    @NonNull final List<TssMessage> validTssMessages) {
                return participantDirectory.getOwnedShareIds().stream()
                        .map(sid -> new TssPrivateShare(
                                sid,
                                new BlsPrivateKey(
                                        signatureSchema
                                                .getPairingFriendlyCurve()
                                                .field()
                                                .fromLong(sid),
                                        signatureSchema)))
                        .toList();
            }

            @NonNull
            @Override
            public List<TssPublicShare> obtainPublicShares(
                    @NonNull final TssParticipantDirectory participantDirectory,
                    @NonNull final List<TssMessage> tssMessages) {
                return participantDirectory.getShareIds().stream()
                        .map(sid -> new TssPublicShare(
                                sid,
                                new BlsPrivateKey(
                                                signatureSchema
                                                        .getPairingFriendlyCurve()
                                                        .field()
                                                        .fromLong(sid),
                                                signatureSchema)
                                        .createPublicKey()))
                        .toList();
            }
        };
    }

    @Override
    public TssServiceRekeyStage rekeyStage() {
        return new TssServiceRekeyStage() {
            @NonNull
            @Override
            public TssMessage generateTssMessage(
                    @NonNull final TssParticipantDirectory pendingParticipantDirectory,
                    @NonNull final TssPrivateShare privateShare) {
                return () -> new byte[0];
            }

            @Override
            public boolean verifyTssMessage(
                    @NonNull final TssParticipantDirectory participantDirectory,
                    @Nullable final List<TssPublicShare> publicShares,
                    @NonNull final TssMessage tssMessage) {
                return false;
            }

            @NonNull
            @Override
            public List<TssPrivateShare> obtainPrivateShares(
                    @NonNull final TssParticipantDirectory participantDirectory,
                    @NonNull final List<TssMessage> validTssMessages) {
                return participantDirectory.getOwnedShareIds().stream()
                        .map(sid -> new TssPrivateShare(
                                sid,
                                new BlsPrivateKey(
                                        signatureSchema
                                                .getPairingFriendlyCurve()
                                                .field()
                                                .fromLong(sid),
                                        signatureSchema)))
                        .toList();
            }

            @NonNull
            @Override
            public List<TssPublicShare> obtainPublicShares(
                    @NonNull final TssParticipantDirectory participantDirectory,
                    @NonNull final List<TssMessage> tssMessages) {
                return participantDirectory.getShareIds().stream()
                        .map(sid -> new TssPublicShare(
                                sid,
                                new BlsPrivateKey(
                                                signatureSchema
                                                        .getPairingFriendlyCurve()
                                                        .field()
                                                        .fromLong(sid),
                                                signatureSchema)
                                        .createPublicKey()))
                        .toList();
            }
        };
    }
}
