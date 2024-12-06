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
import com.hedera.cryptography.bls.extensions.serialization.BlsDeserializers;
import com.hedera.cryptography.bls.extensions.serialization.BlsSerializers;
import com.hedera.cryptography.pairings.api.Curve;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class AsciiArmoredFilesTest {
    private static final String BASE_64_KEY = "GpDqPc8HEtomFBh6+USgwcWB1vSx1IMSy2BQXhVWvd0=";
    private static final String BASE_64_KEY_OLD = "AWUoGGXtbZQ8SSfe1LxzvTSmVCuom+DxxXnYx3riBRYl";
    private static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    @TempDir
    Path tempDir;

    @Test
    @Deprecated
    public void testAsciiArmoredWriteKeyReadOldFormat() throws IOException {
        final Path keyPath = tempDir.resolve("test.tss");
        final BlsPrivateKey originalKey =
                BlsPrivateKey.fromBytes(Base64.getDecoder().decode(BASE_64_KEY_OLD));
        String expectedContent = "-----BEGIN PRIVATE KEY-----\n" + BASE_64_KEY_OLD + "\n" + "-----END PRIVATE KEY-----";

        AsciiArmoredFiles.writeKey(keyPath, BlsPrivateKey::toBytes, originalKey);
        assertTrue(keyPath.toFile().exists(), "Key should have been written to file");
        final String fileContents = Files.readString(keyPath);
        assertEquals(expectedContent, fileContents, "File contents should match expected");
        final BlsPrivateKey readKey = AsciiArmoredFiles.readPrivateKey(keyPath);
        assertEquals(BASE_64_KEY_OLD, Base64.getEncoder().encodeToString(readKey.toBytes()));
    }

    @Test
    @SuppressWarnings("ConstantConditions")
    public void testAsciiArmoredWriteKeyRead() throws IOException {
        final Path keyPath = tempDir.resolve("test.tss");
        var deserializer = BlsDeserializers.privateKeyDeserializer(SIGNATURE_SCHEMA);
        var serializer = BlsSerializers.privateKeySerializer();
        final BlsPrivateKey originalKey =
                deserializer.deserialize(Base64.getDecoder().decode(BASE_64_KEY));
        String expectedContent = "-----BEGIN PRIVATE KEY-----\n" + BASE_64_KEY + "\n" + "-----END PRIVATE KEY-----";

        AsciiArmoredFiles.writeKey(keyPath, serializer, originalKey);
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
                        BlsSerializers.privateKeySerializer(),
                        BlsDeserializers.privateKeyDeserializer(SIGNATURE_SCHEMA)
                                .deserialize(Base64.getDecoder().decode(BASE_64_KEY))));
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    @SuppressWarnings("ConstantConditions")
    public void testAsciiArmoredWriteKeyWithNullBase64Key() {
        Exception exception = assertThrows(
                NullPointerException.class,
                () -> AsciiArmoredFiles.writeKey(Path.of("test.tss"), BlsSerializers.publicKeySerializer(), null));
        assertEquals("key must not be null", exception.getMessage());
    }
}
