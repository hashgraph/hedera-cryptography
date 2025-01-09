// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.altbn128.serialization;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.test.fixtures.extensions.serialization.SerializationTester;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@WithRng
public class SerializationTest {

    public static Stream<SerializationTester> arguments() {
        final PairingFriendlyCurve curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128);
        return Stream.of(
                SerializationTester.ethereumSerialization(curve), SerializationTester.defaultSerialization(curve));
    }

    @ParameterizedTest
    @MethodSource("arguments")
    void testSerialization(final SerializationTester tester, final Random r) {
        tester.testAll(r);
    }
}
