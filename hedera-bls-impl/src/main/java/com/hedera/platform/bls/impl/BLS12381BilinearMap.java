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
package com.hedera.platform.bls.impl;

import com.hedera.platform.bls.api.BilinearMap;
import com.hedera.platform.bls.api.Field;
import com.hedera.platform.bls.api.Group;
import com.hedera.platform.bls.api.GroupElement;

/** A bilinear map in the BLS 12-381 family of curves */
public final class BLS12381BilinearMap implements BilinearMap {

    /** The field of the bilinear map */
    private static final Field FIELD = new BLS12381Field();

    /** The group of the bilinear map where BLS signatures reside */
    private static final Group SIGNATURE_GROUP = new BLS12381Group1();

    /** The group of the bilinear map where BLS public keys reside */
    private static final Group KEY_GROUP = new BLS12381Group2();

    /** {@inheritDoc} */
    @Override
    public Field getField() {
        return FIELD;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Since elements are smaller and faster to operate on, we are using {@link BLS12381Group1}
     * as our signature group. More operations are performed with signatures than with keys
     */
    @Override
    public Group getSignatureGroup() {
        return SIGNATURE_GROUP;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Since elements are larger and slower to operate on, we are using {@link BLS12381Group2} as
     * our key group. Fewer operations are performed with keys than with signatures
     */
    @Override
    public Group getKeyGroup() {
        return KEY_GROUP;
    }

    /** {@inheritDoc} */
    @Override
    public boolean comparePairing(
            final GroupElement signatureElement1,
            final GroupElement keyElement1,
            final GroupElement signatureElement2,
            final GroupElement keyElement2) {

        if (!(signatureElement1 instanceof final BLS12381Group1Element signature1)) {
            throw new IllegalArgumentException("signatureElement1 must be a BLS12381Group1Element");
        }

        if (!(keyElement1 instanceof final BLS12381Group2Element key1)) {
            throw new IllegalArgumentException("keyElement1 must be a BLS12381Group2Element");
        }

        if (!(signatureElement2 instanceof final BLS12381Group1Element signature2)) {
            throw new IllegalArgumentException("signatureElement2 must be a BLS12381Group1Element");
        }

        if (!(keyElement2 instanceof final BLS12381Group2Element key2)) {
            throw new IllegalArgumentException("keyElement2 must be a BLS12381Group2Element");
        }

        return BLS12381Bindings.comparePairing(signature1, key1, signature2, key2);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] displayPairing(
            final GroupElement signatureElement, final GroupElement keyElement) {
        if (!(signatureElement instanceof final BLS12381Group1Element signature)) {
            throw new IllegalArgumentException("signatureElement must be a BLS12381Group1Element");
        }

        if (!(keyElement instanceof final BLS12381Group2Element key)) {
            throw new IllegalArgumentException("keyElement must be a BLS12381Group2Element");
        }

        // display output is always this size
        final byte[] output = new byte[1249];

        final int errorCode;
        if ((errorCode = BLS12381Bindings.pairingDisplay(signature, key, output)) != 0) {
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
