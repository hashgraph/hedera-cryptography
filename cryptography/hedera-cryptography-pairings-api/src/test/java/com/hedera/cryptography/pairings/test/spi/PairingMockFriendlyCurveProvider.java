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

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.spi.PairingFriendlyCurveProvider;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *  A mock provider to be used in tests.
 *  Returns a fake {@link PairingFriendlyCurve} implementation not suitable for usage.
 */
public class PairingMockFriendlyCurveProvider extends PairingFriendlyCurveProvider {

    private static final byte[] BYTES = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1
    };

    private static final PairingFriendlyCurve TEST_PAIRING_FRIENDLY_CURVE;

    public static final Curve TEST_CURVE = Curve.ALT_BN128;

    static {
        TEST_PAIRING_FRIENDLY_CURVE =
                new TestPairingFriendlyCurve(TEST_CURVE, new TestField(), new TestGroup(), new TestGroup());
    }

    /**
     * Counts the number of times {@link PairingMockFriendlyCurveProvider#doInit()} method gets invoked
     */
    private final AtomicInteger initializedCount = new AtomicInteger(0);

    /**
     * @return the number of times the {@link PairingMockFriendlyCurveProvider#doInit()}  method got invoked
     */
    public int getInitializedCount() {
        return initializedCount.get();
    }

    /** {@inheritDoc} */
    @Override
    protected void doInit() {
        initializedCount.incrementAndGet();
    }

    /** {@inheritDoc} */
    @Override
    public Curve curve() {
        return TEST_CURVE;
    }

    /** {@inheritDoc} */
    @Override
    public PairingFriendlyCurve pairingFriendlyCurve() {
        return TEST_PAIRING_FRIENDLY_CURVE;
    }

    /**
     * Fake implementation of a {@link PairingFriendlyCurve}
     */
    private record TestPairingFriendlyCurve(
            @NonNull Curve curve, @NonNull Field field, @NonNull Group group, @NonNull Group group2)
            implements PairingFriendlyCurve {

        /** {@inheritDoc} */
        @NonNull
        @Override
        public Field field() {
            return field;
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public Group group1() {
            return group;
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public Group group2() {
            return group2;
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public Group getOtherGroup(@NonNull final Group group) {
            if (group.equals(group2)) {
                return group;
            }
            if (group.equals(this.group)) {
                return group2;
            }
            throw new IllegalArgumentException("group does not belong to this pairing");
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public BilinearPairing pairingBetween(
                @NonNull final GroupElement element1, @NonNull final GroupElement element2) {
            return new BilinearPairing() {
                @NonNull
                @Override
                public GroupElement getInputElement1() {
                    return element1;
                }

                @NonNull
                @Override
                public GroupElement getInputElement2() {
                    return element2;
                }

                @Override
                public boolean compare(final BilinearPairing other) {
                    return true;
                }
            };
        }
    }

    private record TestFieldElement(Field field) implements FieldElement {
        /** {@inheritDoc} */
        @NonNull
        @Override
        public Field getField() {
            return field;
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public FieldElement add(@NonNull final FieldElement other) {
            return new TestFieldElement(field);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public FieldElement subtract(@NonNull final FieldElement other) {
            return new TestFieldElement(field);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public FieldElement multiply(@NonNull final FieldElement other) {
            return new TestFieldElement(field);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public FieldElement power(final long exponent) {
            return new TestFieldElement(field);
        }

        @NonNull
        @Override
        public FieldElement inverse() {
            return new TestFieldElement(field);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public BigInteger toBigInteger() {
            return new BigInteger(toBytes());
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public byte[] toBytes() {
            return BYTES;
        }
    }
    ;

    private static class TestField implements Field {
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
            return TEST_PAIRING_FRIENDLY_CURVE;
        }
    }

    private record TestGroupElement(Group group) implements GroupElement {
        /** {@inheritDoc} */
        @Override
        public int size() {
            return BYTES.length;
        }
        /** {@inheritDoc} */
        @NonNull
        @Override
        public Group getGroup() {
            return group;
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement multiply(@NonNull final FieldElement other) {
            return new TestGroupElement(group);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement add(@NonNull final GroupElement other) {
            return new TestGroupElement(group);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement copy() {
            return new TestGroupElement(group);
        }
        /** {@inheritDoc} */
        @NonNull
        @Override
        public byte[] toBytes() {
            return BYTES;
        }
    }

    private record TestGroup() implements Group {
        /** {@inheritDoc} */
        @NonNull
        @Override
        public PairingFriendlyCurve getPairingFriendlyCurve() {
            return TEST_PAIRING_FRIENDLY_CURVE;
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement generator() {
            return new TestGroupElement(this);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement zero() {
            return new TestGroupElement(this);
        }
        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement random(@NonNull final byte[] seed) {
            return new TestGroupElement(this);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement fromHash(@NonNull final byte[] input) {
            return new TestGroupElement(this);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement batchAdd(@NonNull final Collection<GroupElement> elements) {
            return new TestGroupElement(this);
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public GroupElement fromBytes(@NonNull final byte[] bytes) {
            return new TestGroupElement(this);
        }

        /** {@inheritDoc} */
        @Override
        public int seedSize() {
            return 32;
        }
        /** {@inheritDoc} */
        @Override
        public int elementSize() {
            return 32;
        }
    }
}
