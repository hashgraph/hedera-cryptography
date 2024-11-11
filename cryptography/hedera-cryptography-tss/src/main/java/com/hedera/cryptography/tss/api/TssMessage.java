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
     *  <li>4 fixed bytes representing the version of the message.</li>
     *  <li>1 byte representing the SignatureSchema that originated the message.</li>
     *  <li>4 fixed bytes representing the shareId that originated the message.</li>
     *  <li>4 fixed bytes representing the size <code>n<sub>1</sub></code> of the next list.</li>
     *  <li> a list of <code>n<sub>1</sub></code> elements of {@code g} size representing the shared randomness. (Total of <code>n<sub>1</sub>*g</code> bytes)</li>
     *  <li>4 fixed bytes representing the size M of the next lists.</li>
     *  <li>
     *      <ul>
     *          <li>4 bytes representing the size <code>n<sub>2</sub></code> of the next list</li>
     *          <li>a list of <code>n<sub>2</sub></code> elements of {@code g} size representing the encrypted shares</li>
     *      </ul>
     *      (total of {@code M*N_2*g} bytes)
     *  </li>
     *  <li>4 fixed bytes representing the size <code>n<sub>3</sub></code> of the next list</li>
     *  <li>A list of <code>n<sub>3</sub></code> elements of {@code g} size representing the polynomial commitment (total of <code>n<sub>3</sub>*g</code> bytes) </li>
     *  <li>{@code g} bytes representing the proof {@code f} element</li>
     *  <li>{@code g} bytes representing the proof {@code a} element</li>
     *  <li>{@code s} bytes representing the proof {@code zr} element</li>
     *  <li>{@code s} bytes representing the proof {@code za} element</li>
     *  </ul>
     * @return the byte representation of a TssMessage
     */
    byte[] bytes();
}
