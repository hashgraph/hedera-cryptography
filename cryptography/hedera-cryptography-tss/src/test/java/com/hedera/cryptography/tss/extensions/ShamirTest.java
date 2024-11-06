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
import java.security.SecureRandom;
import java.util.Random;
import org.junit.jupiter.api.Test;

class ShamirTest {
    private static final Random ROOT_RNG = new SecureRandom();

    @Test
    void testNegativeOrZeroDegreeThrowsException() {
        var field = PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                .pairingFriendlyCurve()
                .field();
        assertThrows(
                IllegalArgumentException.class, () -> Shamir.interpolationPolynomial(ROOT_RNG, field.fromLong(0), -1));
        assertThrows(
                IllegalArgumentException.class, () -> Shamir.interpolationPolynomial(ROOT_RNG, field.fromLong(0), 0));
    }

    @Test
    void testNullRandomOrSecretThrowsException() {
        var field = PairingFriendlyCurves.findInstance(Curve.ALT_BN128)
                .pairingFriendlyCurve()
                .field();
        assertThrows(NullPointerException.class, () -> Shamir.interpolationPolynomial(null, field.fromLong(0), 10));
        assertThrows(NullPointerException.class, () -> Shamir.interpolationPolynomial(ROOT_RNG, null, 10));
    }
}
