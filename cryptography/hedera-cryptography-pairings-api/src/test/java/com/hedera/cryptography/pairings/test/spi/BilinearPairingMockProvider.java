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
import java.util.concurrent.atomic.AtomicBoolean;

/**
 *  A mock provider to be used in tests
 */
public class BilinearPairingMockProvider extends BilinearPairingProvider {

    private static class InstanceHolder {
        private static final FieldElement FIELD_ELEMENT;
        private static final Field FIELD;
        private static final GroupElement GROUP_ELEMENT;
        private static final Group GROUP;
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
                public FieldElement add(@NonNull FieldElement other) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement subtract(@NonNull FieldElement other) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement multiply(@NonNull FieldElement other) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement power(@NonNull BigInteger exponent) {
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
                    return new byte[] {
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1
                    };
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
                public FieldElement randomElement(@NonNull byte[] seed) {
                    return FIELD_ELEMENT;
                }

                @NonNull
                @Override
                public FieldElement elementFromBytes(@NonNull byte[] bytes) {
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
                public GroupElement multiply(@NonNull FieldElement other) {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement add(@NonNull GroupElement other) {
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
                    return new byte[] {
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1
                    };
                }
            };
            GROUP = new Group() {
                @NonNull
                @Override
                public BilinearPairing getPairing() {
                    return PAIRING;
                }

                @NonNull
                @Override
                public GroupElement getGenerator() {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement zeroElement() {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement randomElement(@NonNull byte[] seed) {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement elementFromHash(@NonNull byte[] input) {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement batchAdd(@NonNull Collection<GroupElement> elements) {
                    return GROUP_ELEMENT;
                }

                @NonNull
                @Override
                public GroupElement elementFromBytes(@NonNull byte[] bytes) {
                    return GROUP_ELEMENT;
                }

                @Override
                public int getCompressedSize() {
                    return 32;
                }

                @Override
                public int getUncompressedSize() {
                    return 32;
                }

                @Override
                public int getSeedSize() {
                    return 32;
                }
            };

            PAIRING = new BilinearPairingMockProvider.TestBilinearPairing(FIELD, GROUP, GROUP_ELEMENT);
        }
    }

    private static final AtomicBoolean IS_INITIALIZED = new AtomicBoolean(false);

    public static boolean isInitialized() {
        return IS_INITIALIZED.get();
    }

    @Override
    protected void doInit() {
        boolean changed = IS_INITIALIZED.compareAndSet(false, true);
        if (!changed) throw new IllegalStateException("DoInit should only be called before once init");
    }

    @Override
    public Curve curve() {
        return Curve.ALT_BN128;
    }

    @Override
    public BilinearPairing pairing() {
        return InstanceHolder.PAIRING;
    }

    public static class TestBilinearPairing implements BilinearPairing {
        private final Field field;
        private final Group group;
        private final GroupElement groupElement;

        public TestBilinearPairing(Field field, Group group, GroupElement groupElement) {
            this.field = field;
            this.group = group;
            this.groupElement = groupElement;
        }

        @NonNull
        @Override
        public Field getField() {
            return field;
        }

        @NonNull
        @Override
        public Group getGroup1() {
            return group;
        }

        @NonNull
        @Override
        public Group getGroup2() {
            return group;
        }

        @NonNull
        @Override
        public Group getOtherGroup(@NonNull Group group) {
            return this.group;
        }

        @NonNull
        @Override
        public PairingResult pairingBetween(@NonNull GroupElement element1, @NonNull GroupElement element2) {
            return new PairingResult() {
                @NonNull
                @Override
                public GroupElement getInputElement1() {
                    return groupElement;
                }

                @NonNull
                @Override
                public GroupElement getInputElement2() {
                    return groupElement;
                }

                @NonNull
                @Override
                public byte[] getPairingBytes() {
                    return new byte[] {
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1
                    };
                }
            };
        }

        @Override
        public boolean comparePairings(
                @NonNull GroupElement pairingAElement1,
                @NonNull GroupElement pairingAElement2,
                @NonNull GroupElement pairingBElement1,
                @NonNull GroupElement pairingBElement2) {
            return true;
        }
    }
}
