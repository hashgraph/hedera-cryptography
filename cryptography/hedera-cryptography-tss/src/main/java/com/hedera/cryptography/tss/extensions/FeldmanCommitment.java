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

package com.hedera.cryptography.tss.extensions;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A Feldman polynomial commitment.
 *
 * @param commitmentCoefficients the commitment coefficients. Each privateKey in this list consists of the group generator,
 *                               raised to the power of a coefficient of the polynomial being committed to.
 */
public record FeldmanCommitment(@NonNull List<GroupElement> commitmentCoefficients) {
    /**
     * Constructor.
     *
     * @param commitmentCoefficients The commitment coefficients.
     */
    public FeldmanCommitment {
        if (commitmentCoefficients.size() < 2) {
            throw new IllegalArgumentException("Coefficient commitments must have at least 2 elements");
        }
    }

    /**
     * Creates a Feldman commitment.
     *
     * @param group      the group that elements of the commitment are in
     * @param polynomial the polynomial to commit to
     * @return the Feldman commitment
     */
    public static FeldmanCommitment create(@NonNull final Group group, @NonNull final Polynomial polynomial) {
        final GroupElement generator = group.generator();

        final List<GroupElement> commitmentCoefficients = new ArrayList<>();
        for (final FieldElement polynomialCoefficient : polynomial.coefficients()) {
            commitmentCoefficients.add(generator.multiply(polynomialCoefficient));
        }

        return new FeldmanCommitment(commitmentCoefficients);
    }

    /**
     * Evaluates the polynomial at a specific value without reveling the polynomial.
     *
     * @param x the value to evaluate the commitment
     * @return a point on the curve
     */
    @NonNull
    public GroupElement evaluate(@NonNull final FieldElement x) {

        Objects.requireNonNull(x, "x must not be null");
        //         for msg in dkg_messages.iter() {
        //            // compute powers of share_id
        //            let xs = (0..msg.commitment.len()).map(|i| share_id.pow([i as u64])).collect::<Vec<ShareId<G>>>();
        //            let share_of_share_pubkey = msg.commitment.iter().zip(xs.iter()).fold(G::zero(), |acc, (&a_i,
        // &x_i)| { acc + a_i.mul(x_i) });
        //            dealt_share_pubkeys.push(share_of_share_pubkey);
        //        }

        GroupElement result = commitmentCoefficients.getFirst().getGroup().zero();
        for (int i = 0; i < commitmentCoefficients.size(); i++) {
            final FieldElement exponentiatedShareId = x.power(i);
            result = result.add(commitmentCoefficients.get(i).multiply(exponentiatedShareId));
        }

        return result;
    }
}
