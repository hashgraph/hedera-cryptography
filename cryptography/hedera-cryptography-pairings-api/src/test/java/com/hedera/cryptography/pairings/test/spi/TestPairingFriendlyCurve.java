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
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.pairings.test.api.TestCurves;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Fake implementation of a {@link PairingFriendlyCurve}
 */
public abstract class TestPairingFriendlyCurve extends PairingFriendlyCurve {
    private final Curve curve;
    private final Field field;
    private final Group group;
    private final Group group2;

    static final byte[] BYTES = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1
    };

    protected TestPairingFriendlyCurve(final Curve curve) {
        this.curve = curve;
        this.field = new TestField(this);
        this.group = new TestGroup(this);
        this.group2 = new TestGroup(this);
    }

    /** {@inheritDoc} */
    @NonNull
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
    public BilinearPairing pairingBetween(@NonNull final GroupElement element1, @NonNull final GroupElement element2) {
        return new BilinearPairing() {
            @NonNull
            @Override
            public GroupElement first() {
                return element1;
            }

            @NonNull
            @Override
            public GroupElement second() {
                return element2;
            }

            @Override
            public boolean compare(final BilinearPairing other) {
                return true;
            }
        };
    }

    @NonNull
    public Curve curve() {
        return curve;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || obj.getClass() != this.getClass()) {
            return false;
        }
        var that = (TestPairingFriendlyCurve) obj;
        return Objects.equals(this.curve, that.curve)
                && Objects.equals(this.field, that.field)
                && Objects.equals(this.group, that.group)
                && Objects.equals(this.group2, that.group2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(curve, field, group, group2);
    }

    @Override
    public String toString() {
        return "TestPairingFriendlyCurve[" + "curve="
                + curve + ", " + "field="
                + field + ", " + "group="
                + group + ", " + "group2="
                + group2 + ']';
    }

    /**
     * A Test curve under TestCurves.ALT_BN128 enum
     */
    public static class TestAltBn128 extends TestPairingFriendlyCurve {

        public TestAltBn128() {
            super(TestCurves.ALT_BN128);
        }

        /** {@inheritDoc} */
        @Override
        protected void doInit() {}
    }

    /**
     * A Test curve under TestCurves.TEST enum
     */
    public static class TestBn extends TestPairingFriendlyCurve {

        private final AtomicInteger initializedCount = new AtomicInteger(0);
        /** Constructor*/
        public TestBn() {
            super(TestCurves.TEST);
        }

        /** {@inheritDoc} */
        @Override
        protected void doInit() {
            initializedCount.incrementAndGet();
        }

        /**
         * Returns the number of times doInit was called.
         * @return the number of times doInit was called
         */
        public Integer getInitializedCount() {
            return initializedCount.get();
        }
    }

    /**
     * A Test curve that fails in the doInit method
     */
    public static class FailingCurve extends TestPairingFriendlyCurve {

        public FailingCurve() {
            super(TestCurves.FAIL_CURVE);
        }

        /** {@inheritDoc} */
        @Override
        protected void doInit() {
            throw new FailingCurveException("this is a failing provider");
        }
    }

    /**
     * An exception thrown by FailingCurve
     */
    public static class FailingCurveException extends RuntimeException {

        /** {@inheritDoc} */
        public FailingCurveException(final String message) {
            super(message);
        }
    }
}
