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

import static com.hedera.cryptography.utils.test.fixtures.stream.StreamUtils.zipStream;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.bls.BlsKeyPair;
import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.BlsSignature;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

@WithRng
public class AggregationTest {

    @SuppressWarnings("UnnecessaryLocalVariable")
    @Test
    void testTargetGroupIsSameAsOriginal(final Random random) {
        var schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS);
        var dealerSecrets = List.of(
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random));
        var msg =
                """
                        From Wikipedia, the free encyclopedia
                        This article is about plants in the family Araliaceae. For the typographic ornamentation ❧, see Fleuron (typography). For Hedera Hashgraph, see Hashgraph.
                        "Ivy" redirects here. For other plants, see list of plants known as ivy. For other uses, see Ivy (disambiguation).
                        Not to be confused with Hadera.
                        Hedera, commonly called ivy (plural ivies), is a genus of 12–15 species of evergreen climbing or ground-creeping woody plants in the family Araliaceae, native to Western Europe, Central Europe, Southern Europe, Macaronesia, northwestern Africa and across central-southern Asia east to Japan and Taiwan. Several species are cultivated as climbing ornamentals, and the name ivy especially denotes common ivy (Hedera helix), known in North America as "English ivy", which is frequently planted to clothe brick walls.
                        """
                        .getBytes(StandardCharsets.UTF_8);

        final int numberOfParticipants = dealerSecrets.size();
        final int threshold = dealerSecrets.size();
        final var dealerIds =
                IntStream.rangeClosed(1, numberOfParticipants).boxed().toList();

        final var dealersFieldElementsIds = IntStream.rangeClosed(1, numberOfParticipants)
                .boxed()
                .map(schema.getPairingFriendlyCurve().field()::fromLong)
                .toList();
        final var receiverIds = dealerIds;
        final var signatures = dealerSecrets.stream()
                .map(p -> p.privateKey().sign(msg))
                .map(BlsSignature::element)
                .toList();

        final var publicKeys = dealerSecrets.stream()
                .map(BlsKeyPair::publicKey)
                .map(BlsPublicKey::element)
                .toList();
        final var aggregatedPk =
                new BlsPublicKey(Lagrange.recoverGroupElement(dealersFieldElementsIds, publicKeys), schema);
        final var aggregateSignature =
                new BlsSignature(Lagrange.recoverGroupElement(dealersFieldElementsIds, signatures), schema);
        assertTrue(aggregateSignature.verify(aggregatedPk, msg));

        final var aggregatedRekey =
                secretShareAndRecover(dealerSecrets, random, threshold, threshold, schema, receiverIds, dealerIds);

        assertEquals(aggregatedPk.element(), aggregatedRekey);
        assertTrue(aggregateSignature.verify(new BlsPublicKey(aggregatedRekey, schema), msg));
    }

    @Test
    void testTargetGroupIsDifferentAsOriginal(final Random random) {
        var schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS);
        var dealerSecrets = List.of(
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random),
                BlsKeyPair.generate(schema, random));

        final int numberOfParticipants = dealerSecrets.size();
        final int threshold = 12;
        final var dealersIds =
                IntStream.rangeClosed(1, numberOfParticipants).boxed().toList();
        final var dealersFieldElementsIds = dealersIds.stream()
                .map(id -> schema.getPairingFriendlyCurve().field().fromLong(id))
                .toList();
        final var receiverIds =
                IntStream.rangeClosed(1, numberOfParticipants * 2).boxed().toList();

        final var publicKeys = dealerSecrets.stream()
                .map(BlsKeyPair::publicKey)
                .map(BlsPublicKey::element)
                .toList();
        final var aggregatedPk =
                new BlsPublicKey(Lagrange.recoverGroupElement(dealersFieldElementsIds, publicKeys), schema);

        final var aggregatedRekey = secretShareAndRecover(
                dealerSecrets, random, dealersIds.size(), threshold, schema, receiverIds, dealersIds);

        assertEquals(aggregatedPk.element(), aggregatedRekey);
    }

    private GroupElement secretShareAndRecover(
            final List<BlsKeyPair> dealerSecrets,
            final Random random,
            final int previousThreshold,
            final int currentThreshold,
            final SignatureSchema schema,
            final List<Integer> receiverIds,
            final List<Integer> dealersIds) {

        final var selectedDealers = dealersIds.stream()
                .limit(previousThreshold)
                .map(d -> schema.getPairingFriendlyCurve().field().fromLong(d))
                .toList();
        final var privateKeys = dealerSecrets.stream()
                .limit(previousThreshold)
                .map(BlsKeyPair::privateKey)
                .map(BlsPrivateKey::element)
                .toList();
        final var polynomials = privateKeys.stream()
                .map(s -> Shamir.interpolationPolynomial(random, s, currentThreshold - 1))
                .limit(previousThreshold)
                .toList();
        final var polynomialsCommitments = polynomials.stream()
                .map(poly -> Shamir.feldmanCommitment(schema.getPublicKeyGroup(), poly))
                .toList();
        final var polynomialPrivatesPoints = polynomials.stream()
                .map(poly -> receiverIds.stream()
                        .limit(currentThreshold)
                        .map(poly::evaluate)
                        .toList())
                .toList();
        final var polynomialCommitmentsValues = polynomialsCommitments.stream()
                .map(poly -> receiverIds.stream()
                        .limit(currentThreshold)
                        .map(id -> poly.evaluate(
                                schema.getPairingFriendlyCurve().field().fromLong(id)))
                        .toList())
                .toList();

        final var ssPoints = this.reArrange(currentThreshold, polynomialPrivatesPoints);
        final var psPoints = this.reArrange(currentThreshold, polynomialCommitmentsValues);

        final var rekeyPublicShares = psPoints.stream()
                .map(l -> Lagrange.recoverGroupElement(selectedDealers, l))
                .toList();
        final var rekeySecretShares = ssPoints.stream()
                .map(l -> Lagrange.recoverFieldElement(selectedDealers, l))
                .toList();

        zipStream(rekeySecretShares, rekeyPublicShares)
                .forEach(entry -> assertEquals(
                        entry.getValue().getGroup().generator().multiply(entry.getKey()), entry.getValue()));

        final var receiversTssIds = receiverIds.stream()
                .map(d -> schema.getPairingFriendlyCurve().field().fromLong(d))
                .toList();

        return Lagrange.recoverGroupElement(receiversTssIds, rekeyPublicShares);
    }

    private <T> List<List<T>> reArrange(int maxSize, final List<List<T>> polynomialPrivatesPoints) {
        return IntStream.range(0, polynomialPrivatesPoints.getFirst().size())
                .boxed()
                .map(i -> polynomialPrivatesPoints.stream()
                        .map(points -> points.get(i))
                        .toList())
                .limit(maxSize)
                .toList();
    }
}
