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

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.tss.api.TssShareId;
import com.hedera.cryptography.tss.common.HashUtils;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

/**
 * A NizkProof proof.
 *
 */
public class NizkProof {
    private final GroupElement f;
    private final GroupElement a;
    private final GroupElement y;
    private final FieldElement zR;
    private final FieldElement zA;

    /**
     * Creates an instance of a {@link NizkProof}
     * @param f f component of the proof.
     * @param a a component of the proof.
     * @param y y component of the proof.
     * @param zR zR component of the proof.
     * @param zA zA component of the proof.
     */
    private NizkProof(
            final @NonNull GroupElement f,
            @NonNull final GroupElement a,
            @NonNull final GroupElement y,
            @NonNull final FieldElement zR,
            @NonNull final FieldElement zA) {
        this.f = Objects.requireNonNull(f, "f must not be null");
        this.a = Objects.requireNonNull(a, "a must not be null");
        this.y = Objects.requireNonNull(y, " y must not be null");
        this.zR = Objects.requireNonNull(zR, "zR must not be null");
        this.zA = Objects.requireNonNull(zA, "zA must not be null");
    }

    /**
     * Generates a NizkProof proof.
     *
     * @param signatureSchema the signature schema
     * @param random an RNG
     * @param statement the public part of the proof
     * @param witness the private part of the proof
     * @return a {@link NizkProof} proof.
     */
    @NonNull
    public static NizkProof prove(
            @NonNull final SignatureSchema signatureSchema,
            @NonNull final Random random,
            @NonNull final NizkStatement statement,
            @NonNull final NizkWitness witness) {
        final Field field = signatureSchema.getPairingFriendlyCurve().field();
        final Group publicKeyGroup = signatureSchema.getPublicKeyGroup();
        final GroupElement generator = publicKeyGroup.generator();

        // compute x := RO(instance)
        // we do this by seeding a PRNG with the SHA256 hash of the instance (serialized)
        final byte[] statementHash = statement.hash();
        final FieldElement x = field.random(statementHash);

        // Generate random α, ρ ←$ Zp
        final FieldElement alpha = field.random(random);
        final FieldElement rho = field.random(random);

        // compute F = g^rho
        final GroupElement f = generator.multiply(rho);
        // compute A = g^alpha
        final GroupElement a = generator.multiply(alpha);

        // compute Y = Π_{i=1}^{n} (y_i)^x^i
        GroupElement yAggregator = publicKeyGroup.zero();
        for (int i = 0; i < statement.ids().size(); i++) {
            final TssShareId xi = statement.ids().get(i);
            final GroupElement yi = statement.tssEncryptionKeys().get(xi).element();
            yAggregator = yAggregator.add(yi.multiply(x.power(i + 1)));
        }
        final GroupElement y = yAggregator.multiply(rho).add(a);

        // compute x' := RO(F, A, Y)
        final byte[] hash = HashUtils.computeSha256(f.toBytes(), a.toBytes(), y.toBytes());
        final FieldElement xPrime = field.random(hash);

        // compute z_r = x' * r + rho
        final FieldElement z_r = xPrime.multiply(witness.randomness()).add(rho);

        FieldElement sigma = field.fromLong(0L);
        for (int i = 0; i < statement.ids().size(); i++) {
            final FieldElement si = witness.secrets().get(i);
            sigma = sigma.add(si.multiply(x.power(i + 1)));
        }
        // compute z_a = x' * Sigma_{i=1}^{n} (s_i)*x^i + alpha
        final FieldElement z_a = xPrime.multiply(sigma).add(alpha);
        return new NizkProof(f, a, y, z_r, z_a);
    }

    /**
     * Verifies this proof against another statement
     * @param signatureSchema the signature statement
     * @param statement the public information to verify this proof
     * @return true if the statement matches the information used to generate this proof. False otherwise
     */
    public boolean verify(@NonNull final SignatureSchema signatureSchema, @NonNull final NizkStatement statement) {
        final Field field = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null")
                .getPairingFriendlyCurve()
                .field();
        final Group publicKeyGroup = signatureSchema.getPublicKeyGroup();
        // compute x := RO(instance)
        final byte[] statementHash =
                Objects.requireNonNull(statement, "statement must not be null").hash();
        final FieldElement x = field.random(statementHash);
        // compute x' := RO(F, A, Y)
        final byte[] hash = HashUtils.computeSha256(this.f.toBytes(), this.a.toBytes(), this.y.toBytes());
        final FieldElement xPrime = field.random(hash);
        GroupElement lhs;
        GroupElement rhs;

        // check R ^ x' . F = g ^ z_r
        lhs = statement.combinedCiphertext().randomness().multiply(xPrime).add(f);
        rhs = publicKeyGroup.generator().multiply(this.zR);
        if (!lhs.equals(rhs)) {
            return false;
        }

        final List<FieldElement> xPowerI = new ArrayList<>();
        for (int y = 0; y < statement.ids().size(); y++) {
            xPowerI.add(x.power(y + 1));
        }

        List<GroupElement> results = new ArrayList<>();
        final List<GroupElement> polyCoeffs = statement.polynomialCommitment().commitmentCoefficients();
        for (int k = 0; k < polyCoeffs.size(); k++) {
            final GroupElement a_k = polyCoeffs.get(k);
            FieldElement fold = field.fromLong(0L);
            for (int y = 0; y < statement.ids().size(); y++) {
                final TssShareId id = statement.ids().get(y);
                final FieldElement idPowi = id.id().power(k);
                fold = fold.add(idPowi.multiply(xPowerI.get(y)));
            }
            results.add(a_k.multiply(fold));
        }
        GroupElement inner = publicKeyGroup.batchAdd(results);
        lhs = inner.multiply(xPrime).add(this.a);
        rhs = publicKeyGroup.generator().multiply(this.zA);
        if (!lhs.equals(rhs)) {
            return false;
        }

        inner = publicKeyGroup.zero();
        for (int i = 0; i < statement.ids().size(); i++) {
            final GroupElement ci = statement.combinedCiphertext().values().get(i);
            inner = inner.add(ci.multiply(x.power(i + 1)));
        }

        lhs = inner.multiply(xPrime).add(this.y);

        inner = publicKeyGroup.zero();
        for (int i = 0; i < statement.ids().size(); i++) {
            TssShareId idi = statement.ids().get(i);
            GroupElement yi = statement.tssEncryptionKeys().get(idi).element();
            inner = inner.add(yi.multiply(this.zR.multiply(x.power(i + 1))));
        }

        rhs = inner.add(publicKeyGroup.generator().multiply(this.zA));
        return lhs.equals(rhs);
    }
}
