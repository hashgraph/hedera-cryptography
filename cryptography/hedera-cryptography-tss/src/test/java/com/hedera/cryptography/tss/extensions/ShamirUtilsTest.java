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

package com.hedera.cryptography.tss.extensions;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Random;
import org.junit.jupiter.api.Test;

@WithRng
class ShamirUtilsTest {

    @Test
    void testNegativeOrZeroDegreeThrowsException(Random rng) {
        var field = PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                .pairingFriendlyCurve()
                .field();
        assertThrows(
                IllegalArgumentException.class, () -> ShamirUtils.interpolationPolynomial(rng, field.fromLong(0), -1));
        assertThrows(
                IllegalArgumentException.class, () -> ShamirUtils.interpolationPolynomial(rng, field.fromLong(0), 0));
    }

    @Test
    void testNullRandomOrSecretThrowsException(Random rng) {
        var field = PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                .pairingFriendlyCurve()
                .field();
        assertThrows(
                NullPointerException.class, () -> ShamirUtils.interpolationPolynomial(null, field.fromLong(0), 10));
        assertThrows(NullPointerException.class, () -> ShamirUtils.interpolationPolynomial(rng, null, 10));
    }
}
