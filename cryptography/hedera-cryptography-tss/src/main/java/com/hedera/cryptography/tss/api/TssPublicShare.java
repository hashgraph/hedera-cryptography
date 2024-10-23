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

package com.hedera.cryptography.tss.api;

import static java.util.Objects.requireNonNull;

import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.extensions.Lagrange;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Represents a public portion of a shared key.
 * It's a BLS public key with an owner.
 *
 * @param shareId the share ID
 * @param publicKey the public key
 */
public record TssPublicShare(@NonNull TssShareId shareId, @NonNull BlsPublicKey publicKey) {
    /**
     * Constructor
     *
     * @param shareId the share ID
     * @param publicKey the public key
     */
    public TssPublicShare {
        requireNonNull(shareId, "shareId must not be null");
        requireNonNull(publicKey, "publicKey must not be null");
    }

    /**
     * Creates a new instance.
     *
     * @param id id
     * @param publicKey the private key
     * @return a new {@link TssPublicShare}
     */
    public static TssPublicShare of(final int id, @NonNull final BlsPublicKey publicKey) {
        requireNonNull(publicKey, "publicKey must not be null");
        if (id <= 0) {
            throw new IllegalArgumentException("id must be greater than 0");
        }
        return new TssPublicShare(
                new TssShareId(publicKey
                        .signatureSchema()
                        .getPairingFriendlyCurve()
                        .field()
                        .fromLong(id)),
                publicKey);
    }

    /**
     * verifies a signature using.
     *
     * @param signature the signature to verify
     * @param message the signed message
     * @return if the signature is valid.
     */
    boolean verifySignature(@NonNull TssShareSignature signature, final @NonNull byte[] message) {
        requireNonNull(signature, "signature must not be null");
        return signature.signature().verify(this.publicKey(), message);
    }

    /**
     * Aggregate a threshold number of {@link TssPublicShare}s.
     * It is the responsibility of the caller to ensure that the list of public shares meets the required threshold.
     * If the threshold is not met, the public key returned by this method will be invalid.
     * This method is used for two distinct purposes:
     * <ul>
     *     <li>Aggregating public shares to produce the Ledger ID</li>
     *     <li>Aggregating public shares derived from all commitments, to produce the public key for a given share</li>
     * </ul>
     *
     * @param publicShares the public shares to aggregate
     * @return the interpolated public key
     */
    @NonNull
    public static BlsPublicKey aggregate(@NonNull List<TssPublicShare> publicShares) {
        if (Objects.requireNonNull(publicShares, "publicKeys must not be null").size() < 2) {
            throw new IllegalArgumentException("Not enough publicKeys to aggregate");
        }
        final Collection<SignatureSchema> s = publicShares.stream()
                .map(TssPublicShare::publicKey)
                .map(BlsPublicKey::signatureSchema)
                .collect(Collectors.toSet());
        if (s.size() > 1) {
            throw new IllegalArgumentException("publicKeys must not contain more than one schema");
        }
        var xs = publicShares.stream()
                .map(TssPublicShare::shareId)
                .map(TssShareId::id)
                .toList();
        var ys = publicShares.stream()
                .map(TssPublicShare::publicKey)
                .map(BlsPublicKey::element)
                .toList();
        return new BlsPublicKey(
                Lagrange.recoverGroupElement(xs, ys), s.stream().findFirst().orElseThrow());
    }
}
