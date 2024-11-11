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

package com.hedera.cryptography.tss.api;

import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.GroupElement;

/**
 * A message sent as part of either genesis keying, or rekeying.
 */
public interface TssMessage {

    /**
     * Current supported version.
     * All messages using a different version will throw an error when parsed.
     */
    int MESSAGE_CURRENT_VERSION = 0;

    /**
     * Specification of the format:<p>
     *  Given
     *  <ul>
     *      <li>{@code e}: {@link FieldElement#size()}</li>
     *      <li>{@code g}: {@link GroupElement#size()} of {@link SignatureSchema#getPublicKeyGroup()}</li>
     *  </ul>
     * A {@link TssMessage} byte representation will consist of:<br>
     * <ul>
     *     <li>4 bytes (big-endian) representing the version of the message. Usually {@code MESSAGE_CURRENT_VERSION} constant value</li>
     *     <li>1 byte for {@link SignatureSchema} that originated the message. See {@link SignatureSchema#toByte()}</li>
     *     <li>4 bytes (big-endian) representing the shareId that originated the message.</li>
     *     <li>4 bytes (big-endian) representing the size {@code n1} of the shared randomness list.</li>
     *     <li>A list of {@code n1} elements, each of size {@code g} bytes, representing the shared randomness (total of {@code n1 * g} bytes). See {@link GroupElement#toBytes()}</li>
     *     <li>4 bytes (big-endian) representing the number of encrypted share lists, {@code M}.</li>
     *     <li>
     *         For each of the {@code M} encrypted share lists:
     *         <ul>
     *             <li>4 bytes (big-endian) representing the size {@code n2} of the encrypted shares list.</li>
     *             <li>A list of {@code n2} elements, each of size {@code g} bytes, representing the encrypted shares (total of {@code n2 * g} bytes). See {@link GroupElement#toBytes()}</li>
     *         </ul>
     *     </li>
     *     <li>4 bytes (big-endian) representing the size {@code n3} of the polynomial commitment list.</li>
     *     <li>A list of {@code n3} elements, each of size {@code g} bytes, representing the polynomial commitment (total of {@code n3 * g} bytes). See {@link GroupElement#toBytes()}</li>
     *     <li>{@code g} bytes representing the proof element {@code f}. See {@link GroupElement#toBytes()}</li>
     *     <li>{@code g} bytes representing the proof element {@code a}. See {@link GroupElement#toBytes()}</li>
     *     <li>{@code e} bytes representing the proof scalar {@code zr}. See {@link FieldElement#toBytes()}</li>
     *     <li>{@code e} bytes representing the proof scalar {@code za}. See {@link FieldElement#toBytes()}</li>
     * </ul>
     * @return the byte representation of a TssMessage
     */
    byte[] toBytes();
}
