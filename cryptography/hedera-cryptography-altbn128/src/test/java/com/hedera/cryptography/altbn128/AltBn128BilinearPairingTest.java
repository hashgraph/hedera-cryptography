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

import com.hedera.common.testfixtures.WithRng;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;
import java.util.Random;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@WithRng
class AltBn128BilinearPairingTest {

    @Test
    void testBilinearity(Random rand) {

        // Bilinearity: “a”, “b” member of “Fq” (Finite Field), “P” member of “G₁”, and “Q” member of “G₂”,
        // then e(a×P, b×Q) = e(ab×P, Q) = e(P, ab×Q) = e(P, Q)^(ab)
        AltBn128Group g1 = new AltBn128Group(AltBN128CurveGroup.GROUP1);
        AltBn128Group g2 = new AltBn128Group(AltBN128CurveGroup.GROUP2);
        AltBn128Field fq = new AltBn128Field();
        FieldElement a = fq.random(rand);
        FieldElement b = fq.random(rand);
        GroupElement P = g1.random(rand);
        GroupElement Q = g2.random(rand);

        // e(a×P, b×Q) = e(P, ab×Q)
        Assertions.assertTrue(new AltBn128BilinearPairing(P.multiply(a), Q.multiply(b))
                .compare(new AltBn128BilinearPairing(P, Q.multiply(a.multiply(b)))));
        // e(a×P, b×Q) = e(ab×P, Q)
        assertTrue(new AltBn128BilinearPairing(P.multiply(a), Q.multiply(b))
                .compare(new AltBn128BilinearPairing(P.multiply(a.multiply(b)), Q)));

        // e(b×Q,a×P) = e( Q,ab×P)
        assertTrue(new AltBn128BilinearPairing(Q.multiply(b), P.multiply(a))
                .compare(new AltBn128BilinearPairing(Q, P.multiply(a.multiply(b)))));

        // e(a×P, b×Q) = e(P, ab×Q)
        assertTrue(new AltBn128BilinearPairing(Q.multiply(b), P.multiply(a))
                .compare(new AltBn128BilinearPairing(Q.multiply(a.multiply(b)), P)));
    }
}
