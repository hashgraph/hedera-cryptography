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

package com.hedera.cryptography.ecKeyGen;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

/**
 * Writes and reads the base64 string in Pem files according to <a href="https://datatracker.ietf.org/doc/html/rfc7468">...</a>
 */
public class PemFiles {

    /**
     * Reads the content of a PEM file.
     *
     * @param path The location of the file in the fileSystem
     * @param keyType eiter "PUBLIC KEY" or "PRIVATE KEY" string
     * @return the base64 string contained in the PemFile
     * @throws IOException In case of file reading error
     */
    @NonNull
    public static String pemRead(@NonNull final String path, @NonNull final String keyType) throws IOException {
        Objects.requireNonNull(keyType, "keyType must not be null");
        String pemContent = Files.readString(Path.of(Objects.requireNonNull(path, "path must not be null")));

        // Define PEM header and footer
        String header = "-----BEGIN " + keyType + "-----";
        String footer = "-----END " + keyType + "-----";

        // Remove header and footer
        pemContent = pemContent.replace(header, "").replace(footer, "").trim();

        // Remove all line breaks and spaces
        return pemContent.replaceAll("\\s", "");
    }

    /**
     * Writes the content in a PEM file.
     *
     * @param path The location of the file in the fileSystem
     * @param keyType eiter "PUBLIC KEY" or "PRIVATE KEY" string
     * @return the path of where the file was written
     * @throws IOException In case of file reading error
     */
    @NonNull
    public static Path pemWrite(
            @NonNull final String path, @NonNull final String base64Key, @NonNull final String keyType)
            throws IOException {
        String header = "-----BEGIN " + Objects.requireNonNull(keyType, "keyType must not be null") + "-----\n";
        String footer = "-----END " + keyType + "-----\n";
        String content = formatPemContent(Objects.requireNonNull(base64Key, "base64Key must not be null"));

        String pemContent = header + content + footer;

        Files.write(
                Path.of(Objects.requireNonNull(path, "path must not be null")),
                pemContent.getBytes(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
        return Path.of(path);
    }

    /**
     *
     * @implNote
     * Generators MUST wrap the base64-encoded lines so that each line
     *    consists of exactly 64 characters except for the final line, which
     *    will encode the remainder of the data (within the 64-character line
     *    boundary), and they MUST NOT emit extraneous whitespace.  Parsers MAY
     *    handle other line sizes.  These requirements are consistent with PEM
     * @param base64 the base64 string to format according to <a href="https://datatracker.ietf.org/doc/html/rfc7468">...</a>
     * @return the formatted base64 string able to be written in a PEM file.
     */
    //
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
