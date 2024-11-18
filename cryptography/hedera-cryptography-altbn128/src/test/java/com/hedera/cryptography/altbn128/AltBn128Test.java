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

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.curves.KnownCurves;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.math.BigInteger;
import java.util.List;
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

    @Test
    void testCurveProperties() {
        final AltBn128 curve = new AltBn128();
        final Group group1 = curve.group1();
        final Group group2 = curve.group2();

        // Verify curve and group relationships
        assertEquals(KnownCurves.ALT_BN128, curve.curve(), "Curve mismatch!");
        assertEquals(group2, curve.getOtherGroup(group1), "Group relationship mismatch!");
        assertEquals(group1, curve.getOtherGroup(group2), "Group relationship mismatch!");
    }

    @Test
    void testKeyPairGeneration(final Random rng) {
        final AltBn128 curve = new AltBn128();
        final Group group2 = curve.group2();
        final Field field = curve.field();

        // Generate random secret key
        FieldElement sk = field.random(rng);

        // Generate public key
        GroupElement pk = group2.generator().multiply(sk);

        // Verify public key is valid and not null
        assertNotNull(pk, "Public key should not be null!");
    }

    @Test
    void testHashToCurveConsistency(final Random rng) {
        final AltBn128 curve = new AltBn128();
        final Group group1 = curve.group1();

        // Generate random message
        final byte[] msg = new byte[1024];
        rng.nextBytes(msg);

        // Hash to curve
        GroupElement hashed1 = group1.hashToCurve(msg);
        GroupElement hashed2 = group1.hashToCurve(msg);

        // Verify determinism
        assertEquals(hashed1, hashed2, "hashToCurve should be deterministic!");

        // Test invalid input
        assertThrows(NullPointerException.class, () -> group1.hashToCurve(null));
    }

    @Test
    void testPairingOperations(final Random rng) {
        final AltBn128 curve = new AltBn128();
        final Group group1 = curve.group1();
        final Group group2 = curve.group2();
        final Field field = curve.field();

        // Generate random message
        final byte[] msg = new byte[1024];
        rng.nextBytes(msg);

        // Generate random secret key and public key
        FieldElement sk = field.random(rng);
        GroupElement pk = group2.generator().multiply(sk);

        // Hash message to group element
        GroupElement mk = group1.hashToCurve(msg);

        // Perform pairing
        var pairing1 = curve.pairingBetween(mk.multiply(sk), group2.generator());
        var pairing2 = curve.pairingBetween(mk, pk);

        // Validate pairing results
        assertTrue(pairing1.compare(pairing2), "Pairings do not match!");
    }

    @Test
    void testZeroElements(final Random rng) {
        final AltBn128 curve = new AltBn128();
        final Group group1 = curve.group1();
        final Group group2 = curve.group2();
        final AltBn128Field field = (AltBn128Field) curve.field();

        // Test zero elements
        FieldElement zeroScalar = field.zero();
        GroupElement zeroGroupElement1 = group1.zero();
        GroupElement zeroGroupElement2 = group2.zero();

        // pk = 0 * generator = 0
        GroupElement zeroPk = group2.generator().multiply(zeroScalar);
        assertEquals(zeroGroupElement2, zeroPk, "Public key should be zero when scalar is zero!");

        // Pairing with zero should yield zero or identity element
        var zeroPairing = curve.pairingBetween(zeroGroupElement1, zeroGroupElement2);
        assertNotNull(zeroPairing, "Pairing with zero should not be null!");
    }
}
