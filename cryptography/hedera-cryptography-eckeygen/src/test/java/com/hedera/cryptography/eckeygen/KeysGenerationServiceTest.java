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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.hedera.cryptography.eckeygen.KeysGenerationService.KeysServiceException;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class KeysGenerationServiceTest {

    public static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    private static final byte[] SK =
            new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1};
    private static final byte[] PK = new byte[] {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
        7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 4
    };
    private static final byte[][] PAIR = new byte[][] {SK, PK};

    @Test
    public void testGenerateBase64KeyPair() {
        // Given
        final KeyGenerator nativeKeyGenerator = mock(KeyGenerator.class);
        when((nativeKeyGenerator.generateKeyPair(anyInt()))).thenReturn(PAIR);
        KeysGenerationService ks = new KeysGenerationService(SIGNATURE_SCHEMA, nativeKeyGenerator);
        // When
        String[] keyPair = ks.generateBase64KeyPair();

        // then
        assertNotNull(keyPair);
        assertNotNull(keyPair[0]);
        assertNotNull(keyPair[1]);
    }

    @Test
    public void testGenerateBase64KeyPairError() {
        // Given
        final KeyGenerator nativeKeyGenerator = mock(KeyGenerator.class);
        when((nativeKeyGenerator.generateKeyPair(anyInt()))).thenReturn(null);
        KeysGenerationService ks = new KeysGenerationService(SIGNATURE_SCHEMA, nativeKeyGenerator);

        // then
        assertThrows(KeysServiceException.class, ks::generateBase64KeyPair);
    }

    @Test
    public void testGenerateBase64KPublicKey() {
        // Given
        byte[] sk = new byte[] {SIGNATURE_SCHEMA.getIdByte(), 0, 0, 1, 2, 3};
        final KeyGenerator nativeKeyGenerator = mock(KeyGenerator.class);
        when((nativeKeyGenerator.generatePublicKey(anyInt(), any()))).thenReturn(new byte[] {4, 5, 6});
        KeysGenerationService ks = new KeysGenerationService(SIGNATURE_SCHEMA, nativeKeyGenerator);
        // When
        String pk = ks.generateBase64KPublicKey(Base64.getEncoder().encodeToString(sk));

        // then
        assertEquals(Base64.getEncoder().encodeToString(new byte[] {SIGNATURE_SCHEMA.getIdByte(), 0, 0, 4, 5, 6}), pk);
    }
}
