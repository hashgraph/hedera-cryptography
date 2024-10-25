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

package com.hedera.cryptography.tss.extensions.elgamal;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A {@link CiphertextTable} contains for each share an encrypted secret, and the sharedRandomness that was used to produce the encrypted values.
 *
 * @param sharedRandomness a shared randomness for all the messages in {@code shareCiphertexts}
 * @param shareCiphertexts a {@link com.hedera.cryptography.tss.api.TssShareId} to ciphertext table
 */
public record CiphertextTable(
        @NonNull List<GroupElement> sharedRandomness, @NonNull Map<Integer, List<GroupElement>> shareCiphertexts) {

    /**
     * Combines this representation into a compressed representation still containing all the information.
     * This representation is used for Nizk proofs.
     * @param base generally 256 value (which represents all the possibly distinct values we can encrypt in a byte
     * @return the compressed representation of this {@link CiphertextTable}
     */
    @NonNull
    public CombinedCiphertext combine(@NonNull final FieldElement base) {
        final List<GroupElement> ramdomness = new ArrayList<>();

        for (int i = 0; i < this.sharedRandomness().size(); i++) {
            ramdomness.add(this.sharedRandomness().get(i).multiply(base.power(i)));
        }
        final GroupElement c1 = ramdomness.getFirst().getGroup().batchAdd(ramdomness);
        final List<GroupElement> c2 = new ArrayList<>();

        for (int i = 0; i < this.shareCiphertexts().size(); i++) {
            final List<GroupElement> ctxt_i = this.shareCiphertexts().get(i + 1);
            final List<GroupElement> c2_is = new ArrayList<>();
            for (int j = 0; j < ctxt_i.size(); j++) {
                final GroupElement c2_ij = ctxt_i.get(j);
                c2_is.add(c2_ij.multiply(base.power(j)));
            }
            c2.add(c2_is.getFirst().getGroup().batchAdd(c2_is));
        }
        return new CombinedCiphertext(c1, c2);
    }
}
