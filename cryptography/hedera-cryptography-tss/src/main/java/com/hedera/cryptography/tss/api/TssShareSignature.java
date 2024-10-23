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

import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.tss.extensions.Lagrange;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Represents a partial signature created out of a share of a secret key.
 * It's a BLS signature with an owner.
 *
 * @param shareId the share ID
 * @param signature the privateKey
 */
public record TssShareSignature(@NonNull TssShareId shareId, @NonNull BlsSignature signature) {
    /**
     * Constructor.
     *
     * @param shareId   the share ID
     * @param signature the privateKey
     */
    public TssShareSignature {
        requireNonNull(shareId, "shareId must not be null");
        requireNonNull(signature, "signature must not be null");
    }

    /**
     * Creates a new instance.
     *
     * @param id id
     * @param signature the private key
     * @return a new {@link TssShareSignature}
     */
    public static TssShareSignature of(final int id, @NonNull final BlsSignature signature) {
        requireNonNull(signature, "signature must not be null");
        if (id <= 0) {
            throw new IllegalArgumentException("id must be greater than 0");
        }
        return new TssShareSignature(
                new TssShareId(signature
                        .signatureSchema()
                        .getPairingFriendlyCurve()
                        .field()
                        .fromLong(id)),
                signature);
    }

    /**
     * verifies a signature using.
     *
     * @param publicShare the publicShare to verify the signature represented by this instance
     * @param message the signed message
     * @return if the privateKey is valid.
     */
    public boolean verify(@NonNull final TssPublicShare publicShare, @NonNull final byte[] message) {
        Objects.requireNonNull(publicShare, "publicShare must not be null");
        return this.signature.verify(publicShare.publicKey(), message);
    }

    /**
     * Aggregate a threshold number of {@link TssShareSignature}s.
     * It is the responsibility of the caller to ensure that the list of partial signatures meets the required
     * threshold. If the threshold is not met, the privateKey returned by this method will be invalid.
     *
     * @param partialSignatures the list of signatures to aggregate
     * @return the interpolated privateKey
     */
    @NonNull
    public static BlsSignature aggregate(@NonNull List<TssShareSignature> partialSignatures) {
        if (Objects.requireNonNull(partialSignatures, "partialSignatures must not be null")
                        .size()
                < 2) {
            throw new IllegalArgumentException("Not enough partialSignatures to aggregate");
        }
        final Collection<SignatureSchema> s = partialSignatures.stream()
                .map(TssShareSignature::signature)
                .map(BlsSignature::signatureSchema)
                .collect(Collectors.toSet());
        if (s.size() > 1) {
            throw new IllegalArgumentException("publicKeys must not contain more than one schema");
        }
        var xs = partialSignatures.stream()
                .map(TssShareSignature::shareId)
                .map(TssShareId::id)
                .toList();
        var ys = partialSignatures.stream()
                .map(TssShareSignature::signature)
                .map(BlsSignature::element)
                .toList();
        return new BlsSignature(
                Lagrange.recoverGroupElement(xs, ys), s.stream().findFirst().orElseThrow());
    }
}
