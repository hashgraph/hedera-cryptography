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

package com.hedera.cryptography.bls;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.api.curves.KnownCurves;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class SignatureSchemaTest {
    @Test
    void testFindAltBn128Provider() {
        assertDoesNotThrow(() -> PairingFriendlyCurves.findInstance(KnownCurves.ALT_BN128));
        assertEquals(
                KnownCurves.ALT_BN128,
                PairingFriendlyCurves.findInstance(Curve.ALT_BN128).curve(),
                "The pairing friendly curve should be ALT_BN128");
    }

    @ParameterizedTest
    @MethodSource("combinedParameters")
    void crateSignatureSchema(GroupAssignment assignment) {
        final var actual = SignatureSchema.create(Curve.ALT_BN128, assignment);
        assertNotNull(actual, "Should have created a SignatureSchema");
        assertNotNull(actual.getPairingFriendlyCurve(), "Should have created a pairing friendly curve instance");

        assertEquals(
                PairingFriendlyCurves.findInstance(Curve.ALT_BN128),
                actual.getPairingFriendlyCurve(),
                "PairingFriendlyCurve should be a singleton");
        final var g1 = actual.getPairingFriendlyCurve().group1();
        assertEquals(
                g1,
                assignment == GroupAssignment.SHORT_PUBLIC_KEYS
                        ? actual.getPublicKeyGroup()
                        : actual.getSignatureGroup(),
                "group1 assignment validation failed for: " + assignment);
        final var other = SignatureSchema.create(
                Curve.ALT_BN128,
                assignment == GroupAssignment.SHORT_SIGNATURES
                        ? GroupAssignment.SHORT_PUBLIC_KEYS
                        : GroupAssignment.SHORT_SIGNATURES);
        assertNotNull(other, "Should have created a SignatureSchema");
        assertNotNull(other.getPairingFriendlyCurve(), "should have created a pairing friendly curve instance");
    }

    private static Stream<GroupAssignment> combinedParameters() {
        return Arrays.stream(GroupAssignment.values());
    }
}
