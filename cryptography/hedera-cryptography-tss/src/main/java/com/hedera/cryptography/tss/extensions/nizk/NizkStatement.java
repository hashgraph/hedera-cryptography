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
import com.hedera.cryptography.tss.api.TssShareId;
import com.hedera.cryptography.tss.common.HashUtils;
import com.hedera.cryptography.tss.extensions.FeldmanCommitment;
import com.hedera.cryptography.tss.extensions.elgamal.CombinedCiphertext;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The public part of a Nizk proof.
 *
 * @param ids a list of tssIds, should be consecutive and each id value should match the index in the list.
 * @param tssEncryptionKeys a Map to retrieve the corresponding tssEncryptionKey of the participant owning the share
 * @param polynomialCommitment a {@link FeldmanCommitment}
 * @param combinedCiphertext a {@link CombinedCiphertext}
 */
public record NizkStatement(
        @NonNull List<TssShareId> ids,
        @NonNull Map<TssShareId, BlsPublicKey> tssEncryptionKeys,
        @NonNull FeldmanCommitment polynomialCommitment,
        @NonNull CombinedCiphertext combinedCiphertext) {
    /**
     * Constructor.
     */
    public NizkStatement {
        if (Objects.requireNonNull(ids).isEmpty()) throw new IllegalArgumentException("ids cannot be empty");
        if (Objects.requireNonNull(tssEncryptionKeys).isEmpty())
            throw new IllegalArgumentException("tssEncryptionKeys cannot be empty");
        if (ids.size() != tssEncryptionKeys.size())
            throw new IllegalArgumentException("ids.size() != tssEncryptionKeys.size()");
    }

    /**
     * Returns the SHA-256 hash of the information contained in this instance.
     * @return the SHA-256 hash of the information contained in this instance.
     */
    @NonNull
    public byte[] hash() {
        final TssShareId id1 = ids().getFirst();
        final int fieldSize = id1.id().size();
        final int groupSize = tssEncryptionKeys().get(id1).element().size();
        final int size = (ids.size()) * fieldSize
                + (tssEncryptionKeys.size()
                                + polynomialCommitment.commitmentCoefficients().size()
                                + combinedCiphertext.values().size()
                                + 1)
                        * groupSize;
        ByteBuffer bf = ByteBuffer.allocate(size);
        for (TssShareId id : ids) {
            bf.put(id.id().toBytes());
            bf.put(tssEncryptionKeys.get(id).element().toBytes());
        }
        for (GroupElement coefficient : polynomialCommitment.commitmentCoefficients()) {
            bf.put(coefficient.toBytes());
        }
        for (GroupElement cv : combinedCiphertext.values()) {
            bf.put(cv.toBytes());
        }
        bf.put(combinedCiphertext.randomness().toBytes());
        return HashUtils.computeSha256(bf.array());
    }
}
