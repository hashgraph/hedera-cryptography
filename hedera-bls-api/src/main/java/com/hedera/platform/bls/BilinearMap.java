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

/** An object for computing bilinear pairings */
public interface BilinearMap {
    /**
     * Gets the field of the bilinear map
     *
     * @return the field
     */
    Field getField();

    /**
     * Gets the signature group of the map. BLS signatures will be represented as elements of this
     * group
     *
     * @return the signature group of the pairing
     */
    Group getSignatureGroup();

    /**
     * Gets the key group of the map. BLS public keys will be represented as elements of this group
     *
     * @return the key group of the pairing
     */
    Group getKeyGroup();

    /**
     * Computes 2 pairings, and then checks the equality of the result
     *
     * @param signatureElement1 the signature group element of the first pairing
     * @param keyElement1 the key group element of the first pairing
     * @param signatureElement2 the signature group element of the second pairing
     * @param keyElement2 the key group element of the second pairing
     * @return true if the 2 pairings have the same result, otherwise false
     */
    boolean comparePairing(
            final GroupElement signatureElement1,
            final GroupElement keyElement1,
            final GroupElement signatureElement2,
            final GroupElement keyElement2);

    /**
     * Computes a pairing, and returns a string representing the result
     *
     * @param signatureElement the element in the signature group of the pairing
     * @param keyElement the element in the key group of the pairing
     * @return a byte array representing the pairing
     */
    byte[] displayPairing(final GroupElement signatureElement, final GroupElement keyElement);
}
