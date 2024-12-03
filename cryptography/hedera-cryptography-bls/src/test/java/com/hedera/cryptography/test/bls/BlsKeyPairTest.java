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

package com.hedera.cryptography.test.bls;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.bls.BlsKeyPair;
import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Curve;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class BlsKeyPairTest {
    private static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    @Test
    public void generateTest() throws NoSuchAlgorithmException {
        // When
        final BlsKeyPair keyPair = BlsKeyPair.generate(SIGNATURE_SCHEMA);

        // then
        assertNotNull(keyPair);
        assertNotNull(keyPair.privateKey());
        assertNotNull(keyPair.publicKey());
    }

    @Test
    // since we are testing nullity, we are suppressing the warning of passing null
    @SuppressWarnings("ConstantConditions")
    public void nullityChecksTest() {
        assertThrows(NullPointerException.class, () -> new BlsKeyPair(null, null));
        assertThrows(NullPointerException.class, () -> new BlsKeyPair(null, Mockito.mock(BlsPublicKey.class)));
        assertThrows(NullPointerException.class, () -> new BlsKeyPair(Mockito.mock(BlsPrivateKey.class), null));
        assertThrows(NullPointerException.class, () -> BlsKeyPair.generate(null));
    }
}
