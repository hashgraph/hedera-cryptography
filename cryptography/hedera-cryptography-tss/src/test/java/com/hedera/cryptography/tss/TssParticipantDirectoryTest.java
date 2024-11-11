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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.tss.api.TssParticipantDirectory;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class TssParticipantDirectoryTest {

    @Test
    void testInvalidThreshold() {
        final TssParticipantDirectory.Builder builder = TssParticipantDirectory.createBuilder();
        final BlsPublicKey publicKey = mock(BlsPublicKey.class);

        builder.withParticipant(1, 1, publicKey);

        // Test threshold too low

        Exception exception = assertThrows(IllegalArgumentException.class, () -> builder.withThreshold(0));
        assertTrue(exception.getMessage().contains("Invalid threshold: 0"), "threshold check did not work");

        exception = assertThrows(IllegalArgumentException.class, () -> builder.withThreshold(-1));
        assertTrue(exception.getMessage().contains("Invalid threshold: -1"), "threshold check did not work");

        // Test threshold too high
        builder.withThreshold(3);
        exception = assertThrows(IllegalStateException.class, builder::build);
        assertTrue(
                exception.getMessage().contains("Threshold exceeds the number of shares"),
                "threshold check did not work");

        exception = assertThrows(IllegalArgumentException.class, () -> builder.withParticipant(1, 1, publicKey));
        assertTrue(
                exception.getMessage().contains("Participant with id 1 was previously added to the directory"),
                "participant check did not work");
    }

    @Test
    void testEmptyParticipants() {
        final Exception exception = assertThrows(
                IllegalStateException.class,
                () -> TssParticipantDirectory.createBuilder().withThreshold(1).build(),
                "participant check did not work");

        assertTrue(
                exception.getMessage().contains("There should be at least one participant in the protocol"),
                "participant check did not work");
    }

    @Test
    void testValidConstruction() {
        final BlsPublicKey publicKey = mock(BlsPublicKey.class);
        final TssParticipantDirectory directory = TssParticipantDirectory.createBuilder()
                .withParticipant(1, 1, publicKey)
                .withThreshold(1)
                .build();

        assertNotNull(directory, "directory should not be null");
    }

    @Test
    void testValidConstructionHasValidPrivateSharesSize() {
        final BlsPrivateKey privateKey = mock(BlsPrivateKey.class);
        final BlsPublicKey publicKey1 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey2 = mock(BlsPublicKey.class);
        final TssParticipantDirectory directory = TssParticipantDirectory.createBuilder()
                .withParticipant(1, 5, publicKey1)
                .withParticipant(2, 2, publicKey2)
                .withThreshold(1)
                .build();

        assertNotNull(directory, "directory should not be null");
        assertEquals(1, directory.getThreshold());
        assertEquals(List.of(1, 2, 3, 4, 5, 6, 7), directory.getShareIds());
        var keys =
                new BlsPublicKey[] {publicKey1, publicKey1, publicKey1, publicKey1, publicKey1, publicKey2, publicKey2};
        IntStream.range(0, keys.length).forEach(k -> assertEquals(keys[k], directory.getForShareId(k + 1)));
    }

    @Test
    void testGetForShareId() {
        final BlsPrivateKey privateKey = mock(BlsPrivateKey.class);
        final BlsPublicKey publicKey1 = mock(BlsPublicKey.class);
        final BlsPublicKey publicKey2 = mock(BlsPublicKey.class);
        final TssParticipantDirectory directory = TssParticipantDirectory.createBuilder()
                .withParticipant(1, 5, publicKey1)
                .withParticipant(2, 2, publicKey2)
                .withThreshold(1)
                .build();

        assertEquals(publicKey1, directory.getForShareId(1));
        assertEquals(publicKey1, directory.getForShareId(5));
        assertEquals(publicKey2, directory.getForShareId(6));
        assertEquals(publicKey2, directory.getForShareId(7));
        assertThrows(IllegalArgumentException.class, () -> directory.getForShareId(8));
        assertThrows(IllegalArgumentException.class, () -> directory.getForShareId(0));
        assertThrows(IllegalArgumentException.class, () -> directory.getForShareId(-1));
    }
}
