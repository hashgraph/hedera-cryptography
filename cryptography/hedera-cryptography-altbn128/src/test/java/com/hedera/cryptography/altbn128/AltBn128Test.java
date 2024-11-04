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
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.curves.KnownCurves;
import java.util.Random;
import org.junit.jupiter.api.Test;

@WithRng
class AltBn128Test {

    @Test
    void fullCircuit(final Random rng) {
        final AltBn128 curve = new AltBn128();
        final Group group2 = curve.group2();
        final Group group1 = curve.group1();
        final byte[] msg = new byte[1024];
        rng.nextBytes(msg);

        FieldElement sk = curve.field().random(rng);
        GroupElement pk = group2.generator().multiply(sk);
        GroupElement mk = group1.hashToCurve(msg);

        assertEquals(KnownCurves.ALT_BN128, curve.curve());
        assertEquals(group2, curve.getOtherGroup(group1));
        assertEquals(group1, curve.getOtherGroup(group2));
        assertTrue(curve.pairingBetween(mk.multiply(sk), group2.generator()).compare(curve.pairingBetween(mk, pk)));
    }
}
