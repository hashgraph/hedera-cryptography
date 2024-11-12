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

package com.hedera.cryptography.tss.test.fixtures;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.api.TssMessage;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import com.hedera.cryptography.tss.api.TssParticipantPrivateInfo;
import com.hedera.cryptography.tss.api.TssPrivateShare;
import com.hedera.cryptography.tss.api.TssPublicShare;
import com.hedera.cryptography.tss.api.TssService;
import com.hedera.cryptography.tss.api.TssServiceGenesisStage;
import com.hedera.cryptography.tss.api.TssServiceRekeyStage;
import com.hedera.cryptography.tss.api.TssShareExtractor;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;

/**
 * A prototype implementation of the TssService.
 */
public class FakeTssServiceImpl implements TssService {
    private final SignatureSchema signatureSchema;
    private final BlsPrivateKey sharedZeroKey;

    /**
     * Generates a new instance of this prototype implementation.
     *
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     */
    public FakeTssServiceImpl(@NonNull final SignatureSchema signatureSchema) {
        this.signatureSchema = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
        this.sharedZeroKey = new BlsPrivateKey(
                signatureSchema.getPairingFriendlyCurve().field().fromLong(0), signatureSchema);
    }

    @NonNull
    @Override
    public TssServiceGenesisStage genesisStage() {
        return new TssServiceGenesisStage() {

            @NonNull
            @Override
            public TssMessage generateTssMessage(@NonNull final TssParticipantDirectory participantDirectory) {
                return TssTestUtils.testTssMessage(
                        signatureSchema,
                        -1,
                        participantDirectory.getShareIds().size(),
                        participantDirectory.getThreshold());
            }

            @Override
            public boolean verifyTssMessage(
                    @NonNull final TssParticipantDirectory participantDirectory, @NonNull final TssMessage tssMessage) {
                return true;
            }

            @Override
            @NonNull
            public TssShareExtractor shareExtractor(
                    @NonNull final TssParticipantDirectory tssParticipantDirectory,
                    @NonNull final List<TssMessage> messages) {
                return new TssShareExtractor() {
                    @NonNull
                    @Override
                    public TssShareExtractor async(@NonNull final ExecutorService executorService) {
                        return this;
                    }

                    @NonNull
                    @Override
                    public TssShareExtractionStatus status() {
                        return new TssShareExtractionStatus() {
                            @Override
                            public boolean isCompleted() {
                                return false;
                            }

                            @Override
                            public byte percentComplete() {
                                return 0;
                            }

                            @Override
                            public long elapsedTimeMs() {
                                return 0;
                            }

                            @Override
                            public long approximateRemainingTimeMs() {
                                return 0;
                            }
                        };
                    }

                    @NonNull
                    @Override
                    public TssShareExtractor extract(@NonNull final TssParticipantPrivateInfo privateInfo) {
                        return this;
                    }

                    @NonNull
                    @Override
                    public List<TssPrivateShare> ownedPrivateShares(
                            @NonNull TssParticipantPrivateInfo participantPrivateInfo) {
                        return participantPrivateInfo.ownedShares(tssParticipantDirectory).stream()
                                .map(sid -> new TssPrivateShare(sid, sharedZeroKey))
                                .toList();
                    }

                    @NonNull
                    @Override
                    public List<TssPublicShare> allPublicShares() {
                        return tssParticipantDirectory.getShareIds().stream()
                                .map(sid -> new TssPublicShare(sid, sharedZeroKey.createPublicKey()))
                                .toList();
                    }
                };
            }
        };
    }

    @NonNull
    @Override
    public TssServiceRekeyStage rekeyStage() {
        return new TssServiceRekeyStage() {
            @NonNull
            @Override
            public TssMessage generateTssMessage(
                    @NonNull final TssParticipantDirectory tssParticipantDirectory,
                    @NonNull final TssPrivateShare privateShare) {
                return TssTestUtils.testTssMessage(
                        signatureSchema,
                        privateShare.shareId(),
                        tssParticipantDirectory.getShareIds().size(),
                        tssParticipantDirectory.getThreshold());
            }

            @Override
            public boolean verifyTssMessage(
                    @NonNull final TssParticipantDirectory participantDirectory,
                    @Nullable final List<TssPublicShare> previousPublicShares,
                    @NonNull final TssMessage tssMessage) {
                return true;
            }

            @Override
            @NonNull
            public TssShareExtractor shareExtractor(
                    @NonNull final TssParticipantDirectory tssParticipantDirectory,
                    @NonNull final List<TssMessage> messages) {
                return new TssShareExtractor() {
                    @NonNull
                    @Override
                    public TssShareExtractor async(@NonNull final ExecutorService executorService) {
                        return this;
                    }

                    @NonNull
                    @Override
                    public TssShareExtractionStatus status() {
                        return new TssShareExtractionStatus() {

                            @Override
                            public boolean isCompleted() {
                                return false;
                            }

                            @Override
                            public byte percentComplete() {
                                return 0;
                            }

                            @Override
                            public long elapsedTimeMs() {
                                return 0;
                            }

                            @Override
                            public long approximateRemainingTimeMs() {
                                return 0;
                            }
                        };
                    }

                    @NonNull
                    @Override
                    public TssShareExtractor extract(@NonNull final TssParticipantPrivateInfo privateInfo) {
                        return this;
                    }

                    @NonNull
                    @Override
                    public List<TssPrivateShare> ownedPrivateShares(
                            @NonNull TssParticipantPrivateInfo participantPrivateInfo) {
                        return participantPrivateInfo.ownedShares(tssParticipantDirectory).stream()
                                .map(sid -> new TssPrivateShare(sid, sharedZeroKey))
                                .toList();
                    }

                    @NonNull
                    @Override
                    public List<TssPublicShare> allPublicShares() {
                        return tssParticipantDirectory.getShareIds().stream()
                                .map(sid -> new TssPublicShare(sid, sharedZeroKey.createPublicKey()))
                                .toList();
                    }
                };
            }
        };
    }

    @NonNull
    @Override
    public TssMessage messageFromBytes(
            @NonNull final TssParticipantDirectory tssParticipantDirectory, @NonNull final byte[] message) {
        return new OpaqueTssMessage(message);
    }
}
