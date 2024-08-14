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
    private static final String HEADER_FORMAT = "-----BEGIN %s-----\n";
    private static final String FOOTER_FORMAT = "-----END %s-----";
    /**
     * Subset of handled Pem File Types as defined in <a href="https://www.rfc-editor.org/rfc/rfc1422">rfc1422</a>
     */
    public enum PemType {

        /**
         * Represents a private key
         */
        PRIVATE_KEY("PRIVATE KEY"),

        /**
         * Represents a public key
         */
        PUBLIC_KEY("PUBLIC KEY");

        private final String pemTypeName;

        PemType(final String pemTypeName) {
            this.pemTypeName = pemTypeName;
        }

        /**
         * Returns the footer.
         * @return the formatted footer
         */
        public String getFooter() {
            return String.format(FOOTER_FORMAT, pemTypeName);
        }

        /**
         * Returns the formatted header.
         * @return the header
         */
        public String getHeader() {
            return String.format(HEADER_FORMAT, pemTypeName);
        }
    }

    /**
     * Empty constructor for helper static classes
     */
    private PemFiles() {
        // Empty constructor for helper static classes
    }

    /**
     * Reads the content of a PEM file.
     *
     * @param path The location of the file in the fileSystem
     * @param pemType one of the accepted pem types
     * @return the base64 string contained in the PemFile
     * @throws IOException In case of file reading error
     */
    @NonNull
    public static String pemRead(@NonNull final String path, @NonNull final PemType pemType) throws IOException {
        Objects.requireNonNull(pemType, "pemType must not be null");
        final String pemContent = Files.readString(Path.of(Objects.requireNonNull(path, "path must not be null")));
        // Define PEM header and footer
        final String header = pemType.getHeader();
        final String footer = pemType.getFooter();

        // Remove header and footer
        return pemContent.replace(header, "").replace(footer, "").trim().replaceAll("\\s", "");
    }

    /**
     * Writes the content in a PEM file.
     *
     * @param path The location of the file in the fileSystem
     * @param content The content to write to the file
     * @param pemType eiter "PUBLIC KEY" or "PRIVATE KEY" string
     * @return the path of where the file was written
     * @throws IOException In case of file reading error
     */
    @NonNull
    public static Path pemWrite(
            @NonNull final String path, @NonNull final String content, @NonNull final PemType pemType)
            throws IOException {
        Objects.requireNonNull(pemType, "pemType must not be null");
        final String pemContent = pemType.getHeader()
                + formatPemContent(Objects.requireNonNull(content, "content must not be null"))
                + pemType.getFooter();

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
