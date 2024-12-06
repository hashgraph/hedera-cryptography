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

package com.hedera.cryptography.bls;

import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import java.util.Objects;

/**
 *  A bls public Key for a {@code PairingFriendlyCurve} under a specific {@link SignatureSchema}
 * @param element a GroupElement
 * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
 */
public record BlsPublicKey(@NonNull GroupElement element, @NonNull SignatureSchema signatureSchema) {

    /**
     * Constructor
     * @param element the element
     * @param signatureSchema defines which elliptic curve is used in the protocol, and how it's used
     */
    public BlsPublicKey {
        Objects.requireNonNull(element, "element must not be null");
        Objects.requireNonNull(signatureSchema, "signatureSchema must not be null");
    }

    /**
     * Aggregates multiple {@link BlsPublicKey} into a single {@link BlsPublicKey} for efficient verification.
     *<p>
     * This method combines multiple public keys into a single aggregated
     * public key, which retains the same size as a regular {@link BlsPublicKey} .
     * The aggregation is performed using elliptic curve point addition in the group defined by each signature schema,
     * where each publicKey is a point on the curve.
     *<p>
     * An aggregated public key is indistinguishable from a non-aggregated public key in terms of size, reducing the
     * computational cost of verification.
     *
     * @param publicKeys A list of {@link BlsPublicKey}, where each signature is a point in the elliptic
     *                   curve group.
     * @return A single aggregated {@link BlsPublicKey}.
     * @throws NullPointerException if signatures is null.
     * @throws IllegalArgumentException if there are not enough publicKeys to aggregate.
     * @throws IllegalArgumentException if the publicKeys schemas do not match.
     */
    public static BlsPublicKey aggregate(@NonNull final List<BlsPublicKey> publicKeys) {
        if (Objects.requireNonNull(publicKeys, "publicKeys must not be null").size() < 2) {
            throw new IllegalArgumentException("Not enough publicKeys to aggregate");
        }
        if (publicKeys.stream().map(BlsPublicKey::signatureSchema).distinct().count() > 1) {
            throw new IllegalArgumentException("All keys should have the same schema");
        }
        final SignatureSchema schema = publicKeys.getFirst().signatureSchema();
        final List<GroupElement> elements =
                publicKeys.stream().map(BlsPublicKey::element).toList();
        final GroupElement aggregatedElement = schema.getPublicKeyGroup().add(elements);
        return new BlsPublicKey(aggregatedElement, schema);
    }
}
