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

import static com.hedera.cryptography.eckeygen.pem.PemType.PRIVATE_KEY;
import static com.hedera.cryptography.eckeygen.pem.PemType.PUBLIC_KEY;

import com.hedera.cryptography.eckeygen.pem.FileRead;
import com.hedera.cryptography.eckeygen.pem.PemType;
import com.hedera.cryptography.pairings.signatures.api.PairingPrivateKey;
import com.hedera.cryptography.pairings.signatures.api.PairingPublicKey;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.Objects;

/**
 * Writes and reads the base64 string in Pem files according to <a
 * href="https://datatracker.ietf.org/doc/html/rfc7468">...</a>
 */
public class PemFiles {
    /**
     * Empty constructor for helper static classes
     */
    private PemFiles() {
        // Empty constructor for helper static classes
    }

    @NonNull
    public static PairingPrivateKey readPrivateKey(@NonNull final String path) throws IOException {
        final FileRead fileRead = pemRead(path);
        if (fileRead.pemType() != PRIVATE_KEY) {
            throw new IllegalArgumentException("File does not contain a private key");
        }
        return PairingPrivateKey.fromBytes(Base64.getDecoder().decode(fileRead.contents()));
    }

    /**
     * Reads the content of a PEM file.
     *
     * @param path The location of the file in the fileSystem
     * @return the base64 string contained in the PemFile
     * @throws IOException In case of file reading error
     */
    @NonNull
    private static FileRead pemRead(@NonNull final String path) throws IOException {
        final String pemContent = Files.readString(Path.of(Objects.requireNonNull(path, "contents must not be null")));
        final PemType pemType;
        if (pemContent.contains(PRIVATE_KEY.getHeader())) {
            pemType = PRIVATE_KEY;
        } else if (pemContent.contains(PUBLIC_KEY.getHeader())) {
            pemType = PUBLIC_KEY;
        } else {
            throw new IllegalArgumentException("Invalid PEM file");
        }

        // Remove header and footer
        final String contents = pemContent
                .replace(pemType.getHeader(), "")
                .replace(pemType.getFooter(), "")
                .trim()
                .replaceAll("\\s", "");
        return new FileRead(contents, pemType);
    }

    public static Path writeKey(
            @NonNull final String path, @NonNull final PairingPrivateKey privateKey) throws IOException {
        return writeKey(path, Base64.getEncoder().encodeToString(privateKey.toBytes()), PRIVATE_KEY);
    }

    public static Path writeKey(
            @NonNull final String path, @NonNull final PairingPublicKey publicKey) throws IOException {
        return writeKey(path, Base64.getEncoder().encodeToString(publicKey.toBytes()), PemType.PUBLIC_KEY);
    }

    /**
     * Writes the content in a PEM file.
     *
     * @param path    The location of the file in the fileSystem
     * @param content The content to write to the file
     * @param pemType eiter "PUBLIC KEY" or "PRIVATE KEY" string
     * @return the contents of where the file was written
     * @throws IOException In case of file reading error
     */
    @NonNull
    private static Path writeKey(
            @NonNull final String path, @NonNull final String content, @NonNull final PemType pemType)
            throws IOException {
        Objects.requireNonNull(pemType, "pemType must not be null");
        final String pemContent = pemType.getHeader()
                + formatPemContent(Objects.requireNonNull(content, "content must not be null"))
                + pemType.getFooter();

        Files.write(
                Path.of(Objects.requireNonNull(path, "contents must not be null")),
                pemContent.getBytes(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
        return Path.of(path);
    }

    /**
     * @param base64 the base64 string to format according to <a
     *               href="https://datatracker.ietf.org/doc/html/rfc7468">...</a>
     * @return the formatted base64 string able to be written in a PEM file.
     * @implNote Generators MUST wrap the base64-encoded lines so that each line consists of exactly 64 characters
     * except for the final line, which will encode the remainder of the data (within the 64-character line boundary),
     * and they MUST NOT emit extraneous whitespace.  Parsers MAY handle other line sizes.  These requirements are
     * consistent with PEM
     */
    @NonNull
    private static String formatPemContent(@NonNull final String base64) {
        StringBuilder builder = new StringBuilder();
        int index = 0;
        while (index < Objects.requireNonNull(base64, "base64 must not be null").length()) {
            builder.append(base64, index, Math.min(index + 64, base64.length()));
            builder.append("\n");
            // Insert line breaks every 64 characters to conform with PEM format standards
            index += 64;
        }
        return builder.toString();
    }
}
