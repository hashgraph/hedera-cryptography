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

package com.hedera.cryptography.pairings.test.spi;

import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;

/**
 * Fake implementation of a {@link Field}
 */
record TestField(PairingFriendlyCurve curve) implements Field {
    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement fromLong(long inputLong) {
        return new TestFieldElement(this);
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement random(@NonNull final byte[] seed) {
        return new TestFieldElement(this);
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement fromBytes(@NonNull final byte[] bytes) {
        return new TestFieldElement(this);
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public FieldElement fromBigInteger(@NonNull final BigInteger bigInteger) {
        return new TestFieldElement(this);
    }

    /** {@inheritDoc} */
    @Override
    public int elementSize() {
        return 32;
    }

    /** {@inheritDoc} */
    @Override
    public int seedSize() {
        return 32;
    }

    /** {@inheritDoc} */
    @NonNull
    @Override
    public PairingFriendlyCurve getPairingFriendlyCurve() {
        return curve;
    }
}
