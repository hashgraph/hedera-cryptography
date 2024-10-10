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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.hedera.cryptography.pairings.signatures.api.PairingPrivateKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class PemFilesTest {
    private static final String BASE_64_KEY = "AWUoGGXtbZQ8SSfe1LxzvTSmVCuom+DxxXnYx3riBRYl";

    @TempDir
    Path tempDir;

    @Test
    public void testPemWriteRead() throws IOException {

        final Path keyPath = tempDir.resolve("test.pem");
        final PairingPrivateKey originalKey = PairingPrivateKey.fromBytes(Base64.getDecoder().decode(BASE_64_KEY));
        String expectedContent = "-----BEGIN PRIVATE KEY-----\n" + BASE_64_KEY + "\n" + "-----END PRIVATE KEY-----";

        PemFiles.writeKey(keyPath, originalKey);
        assertTrue(keyPath.toFile().exists(), "Key should have been written to file");
        final String fileContents = Files.readString(keyPath);
        assertEquals(expectedContent, fileContents, "File contents should match expected");
        final PairingPrivateKey readKey = PemFiles.readPrivateKey(keyPath);
        assertEquals(
                BASE_64_KEY,
                Base64.getEncoder().encodeToString(readKey.toBytes()));
    }

    @Test
    public void testPemReadWithNullPath() {
        Exception exception = assertThrows(NullPointerException.class, () -> PemFiles.readPrivateKey(null));
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    public void testPemWriteWithNullPath() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> PemFiles.writeKey(null, PairingPrivateKey.fromBytes(Base64.getDecoder().decode(BASE_64_KEY))));
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    public void testPemWriteWithNullBase64Key() {
        Exception exception = assertThrows(NullPointerException.class,
                () -> PemFiles.writeKey(Path.of("test.pem"), (PairingPrivateKey) null));
        assertEquals("key must not be null", exception.getMessage());
    }
}
