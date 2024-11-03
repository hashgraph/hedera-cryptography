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

package com.hedera.cryptography.tss.extensions.nizk;

import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.tss.api.TssEncryptionKeyResolver;
import com.hedera.cryptography.tss.extensions.FeldmanCommitment;
import com.hedera.cryptography.tss.extensions.elgamal.CombinedCiphertext;
import com.hedera.cryptography.utils.HashUtils;
import com.hedera.cryptography.utils.HashUtils.HashCalculator;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Objects;

/**
 * The public part of a Nizk proof.
 *
 * @param tssShareIds a list of tssIds, should be consecutive and each id value should match the index in the list.
 * @param tssEncryptionKeys a Map to retrieve the corresponding tssEncryptionKey of the participant owning the share
 * @param polynomialCommitment a {@link FeldmanCommitment}
 * @param combinedCiphertext a {@link CombinedCiphertext}
 */
public record NizkStatement(
        @NonNull List<Integer> tssShareIds,
        @NonNull TssEncryptionKeyResolver tssEncryptionKeys,
        @NonNull FeldmanCommitment polynomialCommitment,
        @NonNull CombinedCiphertext combinedCiphertext) {
    /**
     * Constructor.
     */
    public NizkStatement {
        if (Objects.requireNonNull(tssShareIds).isEmpty())
            throw new IllegalArgumentException("tssShareIds cannot be empty");
        Objects.requireNonNull(tssEncryptionKeys);
    }

    /**
     * Returns the SHA-256 hash of the information contained in this instance.
     * @return the SHA-256 hash of the information contained in this instance.
     */
    @NonNull
    public byte[] hash() {

        final HashCalculator calculator = HashUtils.getHashCalculator(HashUtils.SHA256);
        for (Integer shareIds : tssShareIds) {
            calculator.append(shareIds);
            final BlsPublicKey publicKey = tssEncryptionKeys.resolveTssEncryptionKey(shareIds);
            calculator.append(publicKey.element().toBytes());
        }
        for (GroupElement coefficient : polynomialCommitment.commitmentCoefficients()) {
            calculator.append(coefficient.toBytes());
        }
        for (GroupElement cv : combinedCiphertext.values()) {
            calculator.append(cv.toBytes());
        }
        calculator.append(combinedCiphertext.randomness().toBytes());
        return calculator.hash();
    }
}
