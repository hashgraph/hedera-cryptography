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
import com.hedera.cryptography.tss.api.TssShareId;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * A {@link CiphertextTable} contains an encrypted share from an individual secret, to each existing share.
 *
 * @param sharedRandomness a shared randomness for all the messages in {@code shareCiphertexts}
 * @param shareCiphertexts the contained share ciphertexts, in order of the share IDs
 */
public record CiphertextTable(
        @NonNull List<GroupElement> sharedRandomness, @NonNull Map<TssShareId, List<GroupElement>> shareCiphertexts) {

    /**
     * Combines this representation into a compressed representation still containing all the information.
     * This representation is used for Nizk proofs.
     * @param base generally 256 value (which represents all the possibly distinct values we can encrypt in a byte
     * @return the compressed representation of this {@link CiphertextTable}
     */
    @NonNull
    public CombinedCiphertext combine(@NonNull final FieldElement base) {
        //        let c1 = ctxt.ramdomness
        //            .iter().enumerate().fold(
        //                G::Affine::zero(),
        //                |acc, (j, c1_j)|
        //                    acc.add(c1_j.mul(&G::ScalarField::from(256u64).pow([j as u64])).into_affine())
        //                .into_affine()
        //            );
        final List<GroupElement> ramdomness = new ArrayList<>();

        for (int i = 0; i < this.sharedRandomness().size(); i++) {
            ramdomness.add(this.sharedRandomness().get(i).multiply(base.power(i)));
        }
        final GroupElement c0 = ramdomness.getFirst().getGroup().batchAdd(ramdomness);
        //        let mut c2 = Vec::new();
        //        for receiver_i_ctxt in ctxt.ciphertexts.iter() {
        //            let c2_i = receiver_i_ctxt
        //                .iter().enumerate().fold(
        //                    G::Affine::zero(),
        //                    |acc, (j, c2_ij)|
        //                        acc.add(c2_ij.mul(&G::ScalarField::from(256u64).pow([j as u64])).into_affine())
        //                    .into_affine()
        //                );
        //            c2.push(c2_i);
        //        }
        final List<GroupElement> c1 = new ArrayList<>();
        for (final Entry<TssShareId, List<GroupElement>> entry :
                this.shareCiphertexts().entrySet()) {
            final List<GroupElement> shared = new ArrayList<>();
            for (int i = 0; i < entry.getValue().size(); i++) {
                shared.add(entry.getValue().get(i).multiply(base.power(i)));
            }
            c1.add(shared.getFirst().getGroup().batchAdd(shared));
        }
        return new CombinedCiphertext(c0, c1);
    }
}
