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

package com.hedera.cryptography.eckeygen;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import com.hedera.cryptography.pairings.signatures.api.PairingKeyPair;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

class KeysGenerationServiceTest {

    public static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    @Test
    public void testGenerateBase64KeyPair() throws NoSuchAlgorithmException {
        // Given
        KeysGenerationService ks = new KeysGenerationService(SIGNATURE_SCHEMA);
        // When
        final PairingKeyPair keyPair = ks.generateKeyPair();

        // then
        assertNotNull(keyPair);
        assertNotNull(keyPair.privateKey());
        assertNotNull(keyPair.publicKey());
    }

    @Test
    public void testGenerateBase64KeyPairError() {
        // Given
        final SignatureSchema mockSchema = mock(SignatureSchema.class);
        KeysGenerationService ks = new KeysGenerationService(mockSchema);

        // then
        assertThrows(NullPointerException.class, ks::generateKeyPair);
    }
}
