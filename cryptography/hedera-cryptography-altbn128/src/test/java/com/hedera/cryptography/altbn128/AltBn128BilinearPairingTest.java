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

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.utils.ByteArrayUtils;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.Test;

@WithRng
class AltBn128BilinearPairingTest {

    @Test
    void testBilinearityWithRandomValues(final Random rand) {
        // Bilinearity: “a”, “b” member of “Fq” (Finite Field), “P” member of “G₁”, and “Q” member of “G₂”,
        // then e(a×P, b×Q) = e(ab×P, Q) = e(P, ab×Q) = e(P, Q)^(ab)
        final AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        final AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final AltBn128Field fq = new AltBn128Field();

        final FieldElement a = fq.random(rand);
        final FieldElement b = fq.random(rand);
        final GroupElement P = g1.random(rand);
        final GroupElement Q = g2.random(rand);

        testBilinearityProperties(a, b, P, Q);
    }

    @Test
    void testBilinearity() {
        final AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        final AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final AltBn128Field fq = new AltBn128Field();

        final FieldElement a = fq.fromLong(1); // Identity scalar
        final FieldElement b = fq.fromLong(0); // Zero scalar
        final GroupElement P = g1.generator();
        final GroupElement Q = g2.generator();

        // Test with edge case values
        testBilinearityProperties(a, b, P, Q);
    }

    private void testBilinearityProperties(
            final FieldElement a, final FieldElement b, final GroupElement P, final GroupElement Q) {
        final AltBn128BilinearPairing pairing1 = new AltBn128BilinearPairing(P.multiply(a), Q.multiply(b));
        final AltBn128BilinearPairing pairing2 = new AltBn128BilinearPairing(P, Q.multiply(a.multiply(b)));
        final AltBn128BilinearPairing pairing3 = new AltBn128BilinearPairing(P.multiply(a.multiply(b)), Q);

        // e(a×P, b×Q) = e(P, ab×Q)
        assertTrue(pairing1.compare(pairing2), "Pairing e(a×P, b×Q) != e(P, ab×Q)");

        // e(a×P, b×Q) = e(ab×P, Q)
        assertTrue(pairing1.compare(pairing3), "Pairing e(a×P, b×Q) != e(ab×P, Q)");

        // e(b×Q, a×P) = e(Q, ab×P)
        final AltBn128BilinearPairing pairing4 = new AltBn128BilinearPairing(Q.multiply(b), P.multiply(a));
        final AltBn128BilinearPairing pairing5 = new AltBn128BilinearPairing(Q, P.multiply(a.multiply(b)));
        assertTrue(pairing4.compare(pairing5), "Pairing e(b×Q, a×P) != e(Q, ab×P)");

        // e(a×P, b×Q) = e(Q, ab×P)
        assertTrue(pairing4.compare(pairing2), "Pairing e(a×P, b×Q) != e(Q, ab×P)");
    }

    @Test
    void testPairingWithZeroElement() {
        final AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        final AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        final AltBn128Field fq = new AltBn128Field();

        final FieldElement zero = fq.zero();
        final GroupElement zeroP = g1.zero();
        final GroupElement zeroQ = g2.zero();

        // Pairing with zero elements should behave consistently
        final AltBn128BilinearPairing zeroPairing1 = new AltBn128BilinearPairing(zeroP, zeroQ);
        final AltBn128BilinearPairing zeroPairing2 =
                new AltBn128BilinearPairing(g1.generator().multiply(zero), g2.generator());

        assertTrue(zeroPairing1.compare(zeroPairing2), "Pairing with zero elements should match!");
    }

    @Test
    void testPairingWithGenerators() {
        final AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        final AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);

        final GroupElement G1 = g1.generator();
        final GroupElement G2 = g2.generator();

        // Pair generators directly
        final AltBn128BilinearPairing pairing1 = new AltBn128BilinearPairing(G1, G2);
        final AltBn128BilinearPairing pairing2 = new AltBn128BilinearPairing(G1, G2);

        assertTrue(pairing1.compare(pairing2), "Pairing should match!");
    }

    /**
     * This test used a precomputed value to verify the bilinearity property of the pairing function. The value was
     * computed using the following python code: <br>
     * <pre>
     *     from py_ecc.bn128 import G1, G2, pairing, multiply
     *
     *     ## Pairing
     *     A = multiply(G2, 5)
     *     B = multiply(G1, 6)
     *     print("A:", A)
     *     print("B:", B)
     *
     *     p1 = pairing(A, B)
     *     print("p1:", p1)
     * </pre>
     */
    @Test
    void testPairingWithMultiples() {
        final AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        final AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);

        // Precomputed values from the Python output
        final BigInteger a1 =
                new BigInteger("20954117799226682825035885491234530437475518021362091509513177301640194298072");
        final BigInteger a2 =
                new BigInteger("4540444681147253467785307942530223364530218361853237193970751657229138047649");
        final BigInteger a3 =
                new BigInteger("21508930868448350162258892668132814424284302804699005394342512102884055673846");
        final BigInteger a4 =
                new BigInteger("11631839690097995216017572651900167465857396346217730511548857041925508482915");
        final GroupElement A = new AltBn128GroupElement(g2, ByteArrayUtils.toLittleEndianBytes(128, a1, a2, a3, a4));

        final BigInteger b1 =
                new BigInteger("4503322228978077916651710446042370109107355802721800704639343137502100212473");
        final BigInteger b2 =
                new BigInteger("6132642251294427119375180147349983541569387941788025780665104001559216576968");
        final GroupElement B = new AltBn128GroupElement(g1, ByteArrayUtils.toLittleEndianBytes(64, b1, b2));

        final AltBn128BilinearPairing p1 = new AltBn128BilinearPairing(A, B);
        final AltBn128BilinearPairing p2 = new AltBn128BilinearPairing(
                g1.generator().multiply(new AltBn128Field().fromLong(6)),
                g2.generator().multiply(new AltBn128Field().fromLong(5)));

        assertTrue(p1.compare(p2), "Pairing should match!");
    }
}
