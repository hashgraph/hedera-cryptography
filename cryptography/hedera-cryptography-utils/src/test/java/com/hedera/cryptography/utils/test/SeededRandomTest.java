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

package com.hedera.cryptography.utils.test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.hedera.cryptography.utils.test.fixtures.rng.SeededRandom;
import com.hedera.cryptography.utils.test.fixtures.rng.WithRng;
import java.util.Random;
import org.junit.jupiter.api.Test;

@WithRng
class SeededRandomTest {

    @Test
    void testConstruction() {
        assertDoesNotThrow(() -> new SeededRandom());
    }

    @Test
    void testConstructionWithSeed() {
        final Random random = new Random();
        final long seed = random.nextLong();

        final SeededRandom seedRandom = new SeededRandom(seed);

        assertNotNull(seedRandom);
        assertEquals(seed, seedRandom.getSeed());
    }

    @Test
    void testInjectedRandom(final SeededRandom random) {
        assertNotNull(random);
        assertNotNull(random.randomBytes(12));
    }

    @Test
    void testInjectedRandom(final Random random) {
        assertNotNull(random);
    }
}
