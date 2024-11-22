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

package com.hedera.cryptography.pairings.test.fixtures.curve;

import com.hedera.cryptography.pairings.api.Curve;

public enum TestFixtureCurves implements Curve {
    NO_PAIRING_CURVE((byte) 0),
    NON_EXISTENT_CURVE((byte) 1),
    FAIL_CURVE((byte) 2),
    TEST((byte) 3);

    /**
     * An internal unique id per curve.
     */
    final byte id;

    TestFixtureCurves(byte id) {
        this.id = id;
    }

    @Override
    public byte getId() {
        return id;
    }
}
