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

package com.hedera.cryptography.pairings.test.extensions.serialization;

import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.pairings.test.fixtures.curve.TestFixtureCurves;
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
                SerializationTester.ethereumSerialization(curve),
                SerializationTester.defaultSerialization(curve));
    }

    @ParameterizedTest
    @MethodSource("arguments")
    void serDesRandom(final SerializationTester tester, final Random r) {
        tester.testAll(r);
    }
}
