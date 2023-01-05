/*
 * Copyright (C) 2022-2023 Hedera Hashgraph, LLC
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
package com.hedera.platform.bls;

/** A bilinear map in the BLS 12-381 family of curves */
public final class BLS12381BilinearMap implements BilinearMap {
    /** {@inheritDoc} */
    @Override
    public Field getField() {
        return new BLS12381Field();
    }

    /**
     * {@inheritDoc}
     *
     * <p>Since elements are smaller and faster to operate on, we are using {@link BLS12381Group1}
     * as our signature group. More operations are performed with signatures than with keys
     */
    @Override
    public Group getSignatureGroup() {
        return new BLS12381Group1();
    }

    /**
     * {@inheritDoc}
     *
     * <p>Since elements are larger and slower to operate on, we are using {@link BLS12381Group2} as
     * our key group. Fewer operations are performed with keys than with signatures
     */
    @Override
    public Group getKeyGroup() {
        return new BLS12381Group2();
    }

    /** {@inheritDoc} */
    @Override
    public boolean comparePairing(
            final GroupElement signatureElement1,
            final GroupElement keyElement1,
            final GroupElement signatureElement2,
            final GroupElement keyElement2) {

        if (signatureElement1 == null
                || keyElement1 == null
                || signatureElement2 == null
                || keyElement2 == null) {
            throw new IllegalArgumentException("all arguments must be valid");
        }

        return BLS12381Bindings.comparePairing(
                (BLS12381Group1Element) signatureElement1,
                (BLS12381Group2Element) keyElement1,
                (BLS12381Group1Element) signatureElement2,
                (BLS12381Group2Element) keyElement2);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] displayPairing(
            final GroupElement signatureElement, final GroupElement keyElement) {
        if (signatureElement == null || keyElement == null) {
            throw new IllegalArgumentException("all arguments must be valid");
        }

        // display output is always this size
        final byte[] output = new byte[1249];

        final int errorCode;
        if ((errorCode =
                        BLS12381Bindings.pairingDisplay(
                                (BLS12381Group1Element) signatureElement,
                                (BLS12381Group2Element) keyElement,
                                output))
                != 0) {

            throw new BLS12381Exception("pairingDisplay", errorCode);
        }

        return output;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null) {
            return false;
        }

        return getClass() == o.getClass();
    }

    @Override
    public int hashCode() {
        return this.getClass().getCanonicalName().hashCode();
    }

    @Override
    public String toString() {
        return this.getClass().getCanonicalName();
    }
}
