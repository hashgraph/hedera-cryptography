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
import com.hedera.cryptography.pairings.api.PairingResult;
import com.hedera.cryptography.pairings.spi.BilinearPairingProvider;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.math.BigInteger;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *  A mock provider to be used in tests.
 *  Returns a fake {@link BilinearPairing} implementation not suitable for usage.
 */
public class BilinearPairingMockProvider extends BilinearPairingProvider {

    private static final byte[] BYTES = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1
    };

    private static class InstanceHolder {
        private static final FieldElement FIELD_ELEMENT;
        private static final Field FIELD;
        private static final Group GROUP;
        private static final Group GROUP2;
        private static final GroupElement GROUP_ELEMENT;
        private static final GroupElement GROUP_ELEMENT2;
        private static final BilinearPairing PAIRING;

        static {
            FIELD_ELEMENT = new FieldElement() {
                @NonNull
                @Override
                public Field getField() {
                    return FIELD;
                }

                @NonNull
                @Override
                public FieldElement add(@NonNull final FieldElement other) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement subtract(@NonNull final FieldElement other) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement multiply(@NonNull final FieldElement other) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement power(@NonNull final BigInteger exponent) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public BigInteger toBigInteger() {
                    return new BigInteger(toBytes());
                }

                @NonNull
                @Override
                public byte[] toBytes() {
                    return BYTES;
                }
            };

            FIELD = new Field() {
                @NonNull
                @Override
                public FieldElement elementFromLong(long inputLong) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement randomElement(@NonNull final byte[] seed) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement elementFromBytes(@NonNull final byte[] bytes) {
                    return FIELD_ELEMENT;
                }

                @Override
                public int getElementSize() {
                    return 32;
                }

                @Override
                public int getSeedSize() {
                    return 32;
                }

                @NonNull
                @Override
                public BilinearPairing getPairing() {
                    return PAIRING;
                }
            };

            GROUP_ELEMENT = new GroupElement() {
                @NonNull
                @Override
                public Group getGroup() {
                    return GROUP;
                }

                @NonNull
                @Override
                public GroupElement multiply(@NonNull final FieldElement other) {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement add(@NonNull final GroupElement other) {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement compress() {
                    return GROUP_ELEMENT;
                }

                @Override
                public boolean isCompressed() {
                    return false;
                }

                @NonNull
                @Override
                public GroupElement copy() {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public byte[] toBytes() {
                    return BYTES;
                }
            };

            GROUP = new Group() {
                /** {@inheritDoc} */
                @NonNull
                @Override
                public BilinearPairing getPairing() {
                    return PAIRING;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement getGenerator() {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement zeroElement() {
                    return GROUP_ELEMENT;
                }
                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement randomElement(@NonNull final byte[] seed) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement elementFromHash(@NonNull final byte[] input) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement batchAdd(@NonNull final Collection<GroupElement> elements) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement elementFromBytes(@NonNull final byte[] bytes) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @Override
                public int getCompressedSize() {
                    return 32;
                }

                /** {@inheritDoc} */
                @Override
                public int getUncompressedSize() {
                    return 32;
                }

                /** {@inheritDoc} */
                @Override
                public int getSeedSize() {
                    return 32;
                }
            };

            GROUP2 = new Group() {
                /** {@inheritDoc} */
                @NonNull
                @Override
                public BilinearPairing getPairing() {
                    return PAIRING;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement getGenerator() {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement zeroElement() {
                    return GROUP_ELEMENT;
                }
                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement randomElement(@NonNull final byte[] seed) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement elementFromHash(@NonNull final byte[] input) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement batchAdd(@NonNull final Collection<GroupElement> elements) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @NonNull
                @Override
                public GroupElement elementFromBytes(@NonNull final byte[] bytes) {
                    return GROUP_ELEMENT;
                }

                /** {@inheritDoc} */
                @Override
                public int getCompressedSize() {
                    return 32;
                }

                /** {@inheritDoc} */
                @Override
                public int getUncompressedSize() {
                    return 32;
                }

                /** {@inheritDoc} */
                @Override
                public int getSeedSize() {
                    return 32;
                }
            };

            GROUP_ELEMENT2 = new GroupElement() {
                @NonNull
                @Override
                public Group getGroup() {
                    return GROUP2;
                }

                @NonNull
                @Override
                public GroupElement multiply(@NonNull final FieldElement other) {
                    return GROUP_ELEMENT2;
                }

                @NonNull
                @Override
                public GroupElement add(@NonNull final GroupElement other) {
                    return GROUP_ELEMENT2;
                }

                @NonNull
                @Override
                public GroupElement compress() {
                    return GROUP_ELEMENT2;
                }

                @Override
                public boolean isCompressed() {
                    return false;
                }

                @NonNull
                @Override
                public GroupElement copy() {
                    return GROUP_ELEMENT2;
                }

                @NonNull
                @Override
                public byte[] toBytes() {
                    return BYTES;
                }
            };

            PAIRING = new BilinearPairingMockProvider.TestBilinearPairing(FIELD, GROUP, GROUP2);
        }
    }

    /**
     * Counts the number of times {@link BilinearPairingMockProvider#doInit()} method gets invoked
     */
    private final AtomicInteger initializedCount = new AtomicInteger(0);

    /**
     * @return the number of times the {@link BilinearPairingMockProvider#doInit()}  method got invoked
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
        return Curve.ALT_BN128;
    }

    /** {@inheritDoc} */
    @Override
    public BilinearPairing pairing() {
        return InstanceHolder.PAIRING;
    }

    /**
     * Fake implementation of a {@link BilinearPairing}
     */
    private record TestBilinearPairing(Field field, Group group, Group group2) implements BilinearPairing {

        /** {@inheritDoc} */
        @NonNull
        @Override
        public Field field() {
            return field;
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public Group getGroup1() {
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
            ;
            if (group.equals(this.group)) {
                return group2;
            }
            throw new IllegalArgumentException("group does not belong to this pairing");
        }

        /** {@inheritDoc} */
        @NonNull
        @Override
        public PairingResult pairingBetween(
                @NonNull final GroupElement element1, @NonNull final GroupElement element2) {
            return new PairingResult() {
                @NonNull
                @Override
                public GroupElement getInputElement1() {
                    return group.zeroElement();
                }

                @NonNull
                @Override
                public GroupElement getInputElement2() {
                    return group2.zeroElement();
                }

                @NonNull
                @Override
                public byte[] getPairingBytes() {
                    return BYTES;
                }
            };
        }

        @Override
        public boolean comparePairings(
                @NonNull final GroupElement pairingAElement1,
                @NonNull final GroupElement pairingAElement2,
                @NonNull final GroupElement pairingBElement1,
                @NonNull final GroupElement pairingBElement2) {
            return true;
        }
    }
}
