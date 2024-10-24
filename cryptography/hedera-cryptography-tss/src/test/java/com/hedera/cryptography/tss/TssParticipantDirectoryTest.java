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

package com.hedera.cryptography.tss;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurve;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class TssParticipantDirectoryTest {

    private SignatureSchema signatureSchema;

    @BeforeEach
    void setUp() {
        signatureSchema = mock(SignatureSchema.class);
        var curve = mock(PairingFriendlyCurve.class);
        when(signatureSchema.getPairingFriendlyCurve()).thenReturn(curve);
        final Field field = mock(Field.class);
        when(curve.field()).thenReturn(field);
        when(field.fromLong(anyLong())).thenReturn(mock(FieldElement.class));
    }

    @Test
    void testInvalidThreshold() {
        final TssParticipantDirectory.Builder builder = TssParticipantDirectory.createBuilder();
        final BlsPrivateKey privateKey = mock(BlsPrivateKey.class);
        final BlsPublicKey publicKey = mock(BlsPublicKey.class);

        builder.withSelf(1, privateKey);
        builder.withParticipant(1, 1, publicKey);

        // Test threshold too low

        Exception exception = assertThrows(IllegalArgumentException.class, () -> builder.withThreshold(0));
        assertTrue(exception.getMessage().contains("Invalid threshold: 0"), "threshold check did not work");

        exception = assertThrows(IllegalArgumentException.class, () -> builder.withThreshold(-1));
        assertTrue(exception.getMessage().contains("Invalid threshold: -1"), "threshold check did not work");

        // Test threshold too high
        builder.withThreshold(3);
        exception = assertThrows(IllegalStateException.class, () -> builder.build(Mockito.mock(SignatureSchema.class)));
        assertTrue(
                exception.getMessage().contains("Threshold exceeds the number of shares"),
                "threshold check did not work");

        exception = assertThrows(IllegalArgumentException.class, () -> builder.withParticipant(1, 1, publicKey));
        assertTrue(
                exception.getMessage().contains("Participant with id 1 was previously added to the directory"),
                "participant check did not work");
    }

    @Test
    void testEmptyBuilder() {
        final TssParticipantDirectory.Builder builder = TssParticipantDirectory.createBuilder();
        final Exception exception = assertThrows(
                IllegalStateException.class, () -> builder.build(signatureSchema), "participant check did not work");
        assertTrue(
                exception.getMessage().contains("There should be an entry for the current participant"),
                "participant check did not work");
    }

    @Test
    void testEmptyParticipants() {
        final BlsPrivateKey privateKey = mock(BlsPrivateKey.class);
        final Exception exception = assertThrows(
                IllegalStateException.class,
                () -> TssParticipantDirectory.createBuilder()
                        .withSelf(1, privateKey)
                        .withThreshold(1)
                        .build(signatureSchema),
                "participant check did not work");

        assertTrue(
                exception.getMessage().contains("There should be at least one participant in the protocol"),
                "participant check did not work");
    }

    @Test
    void testParticipantsDoesNotContainSelf() {
        final BlsPrivateKey privateKey = mock(BlsPrivateKey.class);
        final BlsPublicKey publicKey = mock(BlsPublicKey.class);
        final Exception exception = assertThrows(
                IllegalStateException.class,
                () -> TssParticipantDirectory.createBuilder()
                        .withSelf(1, privateKey)
                        .withParticipant(2, 1, publicKey)
                        .withThreshold(1)
                        .build(signatureSchema),
                "participant check did not work");

        assertTrue(
                exception
                        .getMessage()
                        .contains("The participant list does not contain a reference to the current participant"),
                "participant check did not work");
    }

    @Test
    void testValidConstruction() {
        final BlsPrivateKey privateKey = mock(BlsPrivateKey.class);
        final BlsPublicKey publicKey = mock(BlsPublicKey.class);
        final TssParticipantDirectory directory = TssParticipantDirectory.createBuilder()
                .withSelf(1, privateKey)
                .withParticipant(1, 1, publicKey)
                .withThreshold(1)
                .build(signatureSchema);

        assertNotNull(directory, "directory should not be null");
    }
}
