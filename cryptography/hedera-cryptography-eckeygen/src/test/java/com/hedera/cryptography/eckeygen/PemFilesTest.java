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
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class PemFilesTest {

    @Test
    public void testReadPrivateKey() throws IOException {
        String path = "test.pem";
        String pemContent = "-----BEGIN PRIVATE KEY-----\n"
                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt\n" + "-----END PRIVATE KEY-----";

        try (MockedStatic<Files> mockedFiles = Mockito.mockStatic(Files.class)) {
            mockedFiles.when(() -> Files.readString(Path.of(path))).thenReturn(pemContent);

            final PairingPrivateKey privateKey = PemFiles.readPrivateKey(path);
            assertEquals(
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt",
                    Base64.getEncoder().encodeToString(privateKey.toBytes()));
        }
    }

    @Test
    public void testPemWrite() throws IOException {
        String path = "test.pem";
        final PairingPrivateKey privateKey = PairingPrivateKey.fromBytes(
                Base64.getDecoder().decode("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt"));
        String expectedContent = "-----BEGIN PRIVATE KEY-----\n"
                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt\n" + "-----END PRIVATE KEY-----";

        try (MockedStatic<Files> mockedFiles = Mockito.mockStatic(Files.class)) {
            Path expectedPath = Path.of(path);
            mockedFiles
                    .when(() -> Files.write(
                            eq(expectedPath),
                            any(byte[].class),
                            eq(StandardOpenOption.CREATE),
                            eq(StandardOpenOption.TRUNCATE_EXISTING)))
                    .thenReturn(expectedPath);

            Path resultPath = PemFiles.writeKey(path, privateKey);
            assertEquals(expectedPath, resultPath);

            mockedFiles.verify(() -> Files.write(
                    eq(expectedPath),
                    eq(expectedContent.getBytes()),
                    eq(StandardOpenOption.CREATE),
                    eq(StandardOpenOption.TRUNCATE_EXISTING)));
        }
    }

    @Test
    public void testPemReadWithNullPath() {
        Exception exception = assertThrows(NullPointerException.class, () -> {
            PemFiles.readPrivateKey(null);
        });
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    public void testPemWriteWithNullPath() {
        Exception exception = assertThrows(NullPointerException.class, () -> {
            PemFiles.writeKey(null, mock(PairingPrivateKey.class));
        });
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    public void testPemWriteWithNullBase64Key() {
        Exception exception = assertThrows(NullPointerException.class, () -> {
            PemFiles.writeKey("test.pem", (PairingPrivateKey) null);
        });
        assertEquals("content must not be null", exception.getMessage());
    }
}
