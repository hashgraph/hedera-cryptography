// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.pairings.test.extensions.serialization;

import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves;
import com.hedera.cryptography.pairings.test.fixtures.extensions.serialization.SerializationTester;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@WithRng
public class SerializationTest {

    public static Stream<SerializationTester> arguments() {
        final PairingFriendlyCurve curve = PairingFriendlyCurves.findInstance(TestFixtureCurves.FAKE_CURVE);
        return Stream.of(
                SerializationTester.ethereumSerialization(curve), SerializationTester.defaultSerialization(curve));
    }

    @ParameterizedTest
    @MethodSource("arguments")
    void testSerialization(final SerializationTester tester, final Random r) {
        tester.testAll(r);
    }
}
