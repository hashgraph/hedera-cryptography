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

package com.hedera.cryptography.pairings.test.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import com.hedera.cryptography.pairings.test.spi.PairingMockFriendlyCurveProvider;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class PairingFriendlyCurveProviderTest {

    @Test
    void testFindBilinearPairingFriendlyCurveProvider() {
        assertDoesNotThrow(() -> ServiceLoader.load(PairingFriendlyCurveProvider.class));
        assertDoesNotThrow(
                () -> ServiceLoader.load(PairingFriendlyCurveProvider.class).findFirst());
        assertTrue(() -> ServiceLoader.load(PairingFriendlyCurveProvider.class)
                .findFirst()
                .isPresent());
        assertInstanceOf(
                PairingMockFriendlyCurveProvider.class,
                ServiceLoader.load(PairingFriendlyCurveProvider.class)
                        .findFirst()
                        .get());
    }
}
