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

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

/**
 * A naive implementation of the PairingFriendlyCurve interface for testing purposes.
 * This implementation provides basic methods to interact with the curve, field, and groups.
 */
public class NaiveCurve implements PairingFriendlyCurve {

    /**
     * The size of the field elements in bytes. For simplicity, using 256-bit elements.
     */
    public static final int EXAMPLE_SIZE = 32;

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public Curve curve() {
        return Curve.TEST;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public Field field() {
        return new NaiveField(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public Group group1() {
        return new NaiveGroup(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public Group group2() {
        return new NaiveGroup(this);
    }

    /**
     * Returns the other group associated with this pairing-friendly curve.
     *
     * @param group the group to get the other group for
     * @return the other group
     */
    @Override
    @NonNull
    public Group getOtherGroup(@NonNull final Group group) {
        Objects.requireNonNull(group, "group must not be null");
        return group == group1() ? group2() : group1();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @NonNull
    public BilinearPairing pairingBetween(@NonNull final GroupElement element1, @NonNull final GroupElement element2) {
        Objects.requireNonNull(element1, "element1 must not be null");
        Objects.requireNonNull(element2, "element2 must not be null");
        return new NaiveBilinearPairing(element1, element2);
    }
}
