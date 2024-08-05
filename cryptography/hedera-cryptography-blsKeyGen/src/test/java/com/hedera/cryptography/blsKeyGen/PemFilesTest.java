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

package com.hedera.cryptography.blsKeyGen;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class PemFilesTest {

    @Test
    public void testPemRead() throws IOException {
        String path = "test.pem";
        String keyType = "PRIVATE KEY";
        String pemContent = "-----BEGIN PRIVATE KEY-----\n"
                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt\n" + "-----END PRIVATE KEY-----";

        try (MockedStatic<Files> mockedFiles = Mockito.mockStatic(Files.class)) {
            mockedFiles.when(() -> Files.readString(Path.of(path))).thenReturn(pemContent);

            String base64Content = PemFiles.pemRead(path, keyType);
            assertEquals("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt", base64Content);
        }
    }

    @Test
    public void testPemWrite() throws IOException {
        String path = "test.pem";
        String base64Key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt";
        String keyType = "PRIVATE KEY";
        String expectedContent = "-----BEGIN PRIVATE KEY-----\n"
                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjYgFsPHqHWTzOt\n" + "-----END PRIVATE KEY-----\n";

        try (MockedStatic<Files> mockedFiles = Mockito.mockStatic(Files.class)) {
            Path expectedPath = Path.of(path);
            mockedFiles
                    .when(() -> Files.write(
                            eq(expectedPath),
                            any(byte[].class),
                            eq(StandardOpenOption.CREATE),
                            eq(StandardOpenOption.TRUNCATE_EXISTING)))
                    .thenReturn(expectedPath);

            Path resultPath = PemFiles.pemWrite(path, base64Key, keyType);
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
            PemFiles.pemRead(null, "PRIVATE KEY");
        });
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    public void testPemReadWithNullKeyType() {
        Exception exception = assertThrows(NullPointerException.class, () -> {
            PemFiles.pemRead("test.pem", null);
        });
        assertEquals("keyType must not be null", exception.getMessage());
    }

    @Test
    public void testPemWriteWithNullPath() {
        Exception exception = assertThrows(NullPointerException.class, () -> {
            PemFiles.pemWrite(null, "base64Key", "PRIVATE KEY");
        });
        assertEquals("path must not be null", exception.getMessage());
    }

    @Test
    public void testPemWriteWithNullBase64Key() {
        Exception exception = assertThrows(NullPointerException.class, () -> {
            PemFiles.pemWrite("test.pem", null, "PRIVATE KEY");
        });
        assertEquals("base64Key must not be null", exception.getMessage());
    }

    @Test
    public void testPemWriteWithNullKeyType() {
        Exception exception = assertThrows(NullPointerException.class, () -> {
            PemFiles.pemWrite("test.pem", "base64Key", null);
        });
        assertEquals("keyType must not be null", exception.getMessage());
    }
}
