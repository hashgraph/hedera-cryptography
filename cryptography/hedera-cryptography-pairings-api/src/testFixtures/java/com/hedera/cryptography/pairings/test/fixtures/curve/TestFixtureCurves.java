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
import java.util.concurrent.atomic.AtomicInteger;

public enum TestFixtureCurves implements Curve {
    FAKE_CURVE((byte) 0),
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

    /**
     * A Test curve under TestCurves.FAKE_CURVE enum
     */
    public static class FakeCurve extends NaiveCurve {
        public FakeCurve() {
            super(FAKE_CURVE);
        }
    }

    /**
     * A Test curve under TestCurves.TEST enum
     */
    public static class TestBn extends NaiveCurve {

        private final AtomicInteger initializedCount = new AtomicInteger(0);
        /** Constructor*/
        public TestBn() {
            super(TEST);
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
    public static class FailingCurve extends NaiveCurve {

        public FailingCurve() {
            super(FAIL_CURVE);
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
