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

package com.hedera.cryptography.asciiarmored;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.GroupAssignment;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.bls.extensions.serialization.DefaultBlsPrivateKeySerialization;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.utils.serialization.Serializer;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class AsciiArmoredFilesTest {
    private static final String BASE_64_KEY = "/NpGlCEh4AMwkgBHmpqfJrvYbVf0ss3LspM14kNJVyI=";
    private static final String BASE_64_KEY_OLD = "AWUoGGXtbZQ8SSfe1LxzvTSmVCuom+DxxXnYx3riBRYl";
    private static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);
    /**
     * Packs and unpacks the curve type and group assignment into a single byte
     */
    private static final int CURVE_MASK = 0b01111111; // 7 bits for curve type

    @TempDir
    Path tempDir;

    @Test
    @Deprecated
    public void testAsciiArmoredWriteKeyReadOldFormat() throws IOException {
        final Path keyPath = tempDir.resolve("test.tss");

        final var buffer = Base64.getDecoder().decode(BASE_64_KEY_OLD);
        final var keyBytes = Arrays.copyOfRange(buffer, 1, buffer.length);
        final BlsPrivateKey originalKey = DefaultBlsPrivateKeySerialization.getDeserializer(SIGNATURE_SCHEMA)
                .deserialize(keyBytes);
        String expectedContent = "-----BEGIN PRIVATE KEY-----\n" + BASE_64_KEY_OLD + "\n" + "-----END PRIVATE KEY-----";

        Serializer<BlsPrivateKey> oldSerializer = key -> {
            final var a = DefaultBlsPrivateKeySerialization.getSerializer().serialize(key);
            final var ret1 = new byte[a.length + 1];
            System.arraycopy(a, 0, ret1, 1, a.length);
            ret1[0] = pack(
                    SIGNATURE_SCHEMA.getGroupAssignment(),
                    SIGNATURE_SCHEMA.getCurve().getId());
            return ret1;
        };
        AsciiArmoredFiles.writeKey(keyPath, oldSerializer, originalKey);
        assertTrue(keyPath.toFile().exists(), "Key should have been written to file");
        final String fileContents = Files.readString(keyPath);
        assertEquals(expectedContent, fileContents, "File contents should match expected");
        final BlsPrivateKey readKey = AsciiArmoredFiles.readPrivateKey(keyPath);
        assertEquals(BASE_64_KEY_OLD, Base64.getEncoder().encodeToString(oldSerializer.serialize(readKey)));
    }

    @Test
    @SuppressWarnings("ConstantConditions")
    public void testAsciiArmoredWriteKeyRead() throws IOException {
        final Path keyPath = tempDir.resolve("test.tss");
        var deserializer = DefaultBlsPrivateKeySerialization.getDeserializer(SIGNATURE_SCHEMA);
        var serializer = DefaultBlsPrivateKeySerialization.getSerializer();
        final BlsPrivateKey originalKey =
                deserializer.deserialize(Base64.getDecoder().decode(BASE_64_KEY));
        String expectedContent = "-----BEGIN PRIVATE KEY-----\n" + BASE_64_KEY + "\n" + "-----END PRIVATE KEY-----";

        AsciiArmoredFiles.writeKey(keyPath, DefaultBlsPrivateKeySerialization.getSerializer(), originalKey);
        assertTrue(keyPath.toFile().exists(), "Key should have been written to file");
        final String fileContents = Files.readString(keyPath);
        assertEquals(expectedContent, fileContents, "File contents should match expected");
        final BlsPrivateKey readKey = AsciiArmoredFiles.readPrivateKey(keyPath, deserializer);
        assertEquals(BASE_64_KEY, Base64.getEncoder().encodeToString(serializer.serialize(readKey)));
    }

    @Test
    @SuppressWarnings("ConstantConditions")
    public void testAsciiArmoredReadWithNullPath() {
        Exception exception =
                assertThrows(NullPointerException.class, () -> AsciiArmoredFiles.readPrivateKey(null, null));
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    @SuppressWarnings("ConstantConditions")
    public void testAsciiArmoredWriteKeyWithNullPath() {
        Exception exception = assertThrows(
                NullPointerException.class,
                () -> AsciiArmoredFiles.writeKey(
                        null,
                        DefaultBlsPrivateKeySerialization.getSerializer(),
                        DefaultBlsPrivateKeySerialization.getDeserializer(SIGNATURE_SCHEMA)
                                .deserialize(Base64.getDecoder().decode(BASE_64_KEY))));
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    @SuppressWarnings("ConstantConditions")
    public void testAsciiArmoredWriteKeyWithNullBase64Key() {
        Exception exception = assertThrows(
                NullPointerException.class,
                () -> AsciiArmoredFiles.writeKey(
                        Path.of("test.tss"), DefaultBlsPrivateKeySerialization.getSerializer(), null));
        assertEquals("key must not be null", exception.getMessage());
    }

    /**
     * Packs the group assignment and curve type into a single byte
     *
     * @param groupAssignment the group assignment
     * @param curveType       the curve type
     * @return the packed byte
     */
    @Deprecated
    public static byte pack(@NonNull final GroupAssignment groupAssignment, final byte curveType) {
        if (curveType < 0) {
            throw new IllegalArgumentException("Curve type must be between 0 and 127");
        }

        final int assignmentValue = groupAssignment.getId() << 7;
        return (byte) (assignmentValue | (curveType & CURVE_MASK));
    }
}
