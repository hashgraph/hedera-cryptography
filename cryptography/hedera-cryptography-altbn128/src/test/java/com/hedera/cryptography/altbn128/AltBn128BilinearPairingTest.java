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

package com.hedera.cryptography.altbn128;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Random;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@WithRng
class AltBn128BilinearPairingTest {

    @Test
    void testBilinearityWithRandomValues(final Random rand) {
        // Bilinearity: “a”, “b” member of “Fq” (Finite Field), “P” member of “G₁”, and “Q” member of “G₂”,
        // then e(a×P, b×Q) = e(ab×P, Q) = e(P, ab×Q) = e(P, Q)^(ab)
        AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        AltBn128Field fq = new AltBn128Field();

        FieldElement a = fq.random(rand);
        FieldElement b = fq.random(rand);
        GroupElement P = g1.random(rand);
        GroupElement Q = g2.random(rand);

        testBilinearityProperties(a, b, P, Q);
    }

    @Test
    void testBilinearityWithEdgeValues() {
        AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        AltBn128Field fq = new AltBn128Field();

        FieldElement a = fq.fromLong(1); // Identity scalar
        FieldElement b = fq.fromLong(0); // Zero scalar
        GroupElement P = g1.generator();
        GroupElement Q = g2.generator();

        // Test with edge case values
        testBilinearityProperties(a, b, P, Q);
    }

    private void testBilinearityProperties(FieldElement a, FieldElement b, GroupElement P, GroupElement Q) {
        AltBn128BilinearPairing pairing1 = new AltBn128BilinearPairing(P.multiply(a), Q.multiply(b));
        AltBn128BilinearPairing pairing2 = new AltBn128BilinearPairing(P, Q.multiply(a.multiply(b)));
        AltBn128BilinearPairing pairing3 = new AltBn128BilinearPairing(P.multiply(a.multiply(b)), Q);

        // e(a×P, b×Q) = e(P, ab×Q)
        assertTrue(pairing1.compare(pairing2), "Pairing e(a×P, b×Q) != e(P, ab×Q)");

        // e(a×P, b×Q) = e(ab×P, Q)
        assertTrue(pairing1.compare(pairing3), "Pairing e(a×P, b×Q) != e(ab×P, Q)");

        // e(b×Q, a×P) = e(Q, ab×P)
        AltBn128BilinearPairing pairing4 = new AltBn128BilinearPairing(Q.multiply(b), P.multiply(a));
        AltBn128BilinearPairing pairing5 = new AltBn128BilinearPairing(Q, P.multiply(a.multiply(b)));
        assertTrue(pairing4.compare(pairing5), "Pairing e(b×Q, a×P) != e(Q, ab×P)");

        // e(a×P, b×Q) = e(Q, ab×P)
        assertTrue(pairing4.compare(pairing2), "Pairing e(a×P, b×Q) != e(Q, ab×P)");
    }

    @Test
    void testPairingWithZeroElement() {
        AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        AltBn128Field fq = new AltBn128Field();

        FieldElement zero = fq.zero();
        GroupElement zeroP = g1.zero();
        GroupElement zeroQ = g2.zero();

        // Pairing with zero elements should behave consistently
        AltBn128BilinearPairing zeroPairing1 = new AltBn128BilinearPairing(zeroP, zeroQ);
        AltBn128BilinearPairing zeroPairing2 = new AltBn128BilinearPairing(g1.generator().multiply(zero), g2.generator());

        assertTrue(zeroPairing1.compare(zeroPairing2), "Pairing with zero elements should match!");
    }

    @Test
    void testPairingWithGenerators() {
        AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        AltBn128Field fq = new AltBn128Field();

        GroupElement G1 = g1.generator();
        GroupElement G2 = g2.generator();

        // Pair generators directly
        AltBn128BilinearPairing pairing = new AltBn128BilinearPairing(G1, G2);

        assertNotNull(pairing, "Pairing of generators should not be null!");
    }
}
