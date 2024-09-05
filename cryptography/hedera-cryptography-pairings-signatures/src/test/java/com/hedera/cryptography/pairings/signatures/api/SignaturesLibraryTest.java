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

package com.hedera.cryptography.pairings.signatures.api;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.api.curves.KnownCurves;
import java.security.SecureRandom;
import java.util.Random;
import org.junit.jupiter.api.Test;

class SignaturesLibraryTest {

    @Test
    void testFindAltBn128Provider() {
        assertDoesNotThrow(() -> PairingFriendlyCurves.findInstance(KnownCurves.ALT_BN128));
        assertEquals(
                KnownCurves.ALT_BN128,
                PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                        .pairingFriendlyCurve()
                        .curve());
    }

    @Test
    void crateSignatureSchema() {
        final var actual = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.GROUP1_FOR_PUBLIC_KEY);
        assertNotNull(actual);
        assertNotNull(actual.getPairingFriendlyCurve());

        assertEquals(PairingFriendlyCurves.findInstance(Curve.ALT_BN128).pairingFriendlyCurve(),
                actual.getPairingFriendlyCurve());
        final var g1 =actual.getPairingFriendlyCurve().group1();
        assertEquals(g1, actual.getPublicKeyGroup());
        final var other = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.GROUP1_FOR_SIGNING);
        assertNotNull(other);
        assertNotNull(other.getPairingFriendlyCurve());
        final var g2 =other.getPairingFriendlyCurve().group2();
        assertEquals(g2, other.getPublicKeyGroup());

        assertNotEquals(actual.getIdByte(), other.getIdByte());

        assertEquals(actual, SignatureSchema.create(actual.getIdByte()));
        assertEquals(other, SignatureSchema.create(other.getIdByte()));
    }

    @Test
    void crateKeyPairTest() {
        final var schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.GROUP1_FOR_SIGNING);
        final var rng = new Random();

        final var sk = PairingPrivateKey.create(schema,rng);
        assertNotNull(sk);
        assertNotNull(sk.toBytes());
        assertNotNull(sk.createPublicKey());
        assertNotNull(sk.toBytes());

        final var pk = sk.createPublicKey();
        assertEquals(pk, sk.createPublicKey());

        final byte[] invalidKey = new byte[0];
        assertThrows(IllegalArgumentException.class, ()-> PairingPrivateKey.fromBytes(invalidKey));
        final byte[] invalidKey2 = new byte[]{schema.getIdByte(), 0,0,0,0 };
        assertThrows(IllegalArgumentException.class, ()-> PairingPrivateKey.fromBytes(invalidKey2));

        assertEquals(sk, PairingPrivateKey.fromBytes(sk.toBytes()));
        assertEquals(pk, PairingPublicKey.fromBytes(pk.toBytes()));
        assertThrows(IllegalArgumentException.class, ()-> PairingPublicKey.fromBytes(invalidKey));
        assertThrows(IllegalArgumentException.class, ()-> PairingPublicKey.fromBytes(invalidKey2));
    }

}
