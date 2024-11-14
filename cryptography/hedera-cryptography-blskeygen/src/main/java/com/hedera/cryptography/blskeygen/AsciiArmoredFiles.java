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

package com.hedera.cryptography.blskeygen;

import static com.hedera.cryptography.blskeygen.asciiarmored.AsciiArmoredType.PRIVATE_KEY;
import static com.hedera.cryptography.blskeygen.asciiarmored.AsciiArmoredType.PUBLIC_KEY;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.blskeygen.asciiarmored.AsciiArmoredFile;
import com.hedera.cryptography.blskeygen.asciiarmored.AsciiArmoredType;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.Objects;

/**
 * ASCII-Armor, also known as ASCII Armor, is a technique used to convert binary data into ASCII text format.
 * This encoding ensures that the data remains intact when transmitted or shared across systems or platforms, which might otherwise corrupt the information.
 * It is often employed in email encryption, such as PGP, to safely send encrypted messages as text.
 */
public class AsciiArmoredFiles {
    /**
     * Empty constructor for helper static classes
     */
    private AsciiArmoredFiles() {
        // Empty constructor for helper static classes
    }

    /**
     * Reads a private key from a PEM file.
     *
     * @param path The location of the file in the fileSystem
     * @return the private key contained in the file
     * @throws IOException In case of file reading error
     */
    @NonNull
    public static BlsPrivateKey readPrivateKey(@NonNull final Path path) throws IOException {
        final AsciiArmoredFile fileRead = asciiArmoredRead(Objects.requireNonNull(path, "path must not be null"));
        if (fileRead.asciiArmoredType() != PRIVATE_KEY) {
            throw new IllegalArgumentException("File does not contain a private key");
        }
        return BlsPrivateKey.fromBytes(Base64.getDecoder().decode(fileRead.contents()));
    }

    /**
     * Reads the content of a PEM file.
     *
     * @param path The location of the file in the fileSystem
     * @return the base64 string contained in the PemFile
     * @throws IOException In case of file reading error
     */
    @NonNull
    private static AsciiArmoredFile asciiArmoredRead(@NonNull final Path path) throws IOException {
        final String pemContent = Files.readString(Objects.requireNonNull(path, "contents must not be null"));
        final AsciiArmoredType asciiArmoredType;
        if (pemContent.contains(PRIVATE_KEY.getHeader())) {
            asciiArmoredType = PRIVATE_KEY;
        } else if (pemContent.contains(PUBLIC_KEY.getHeader())) {
            asciiArmoredType = PUBLIC_KEY;
        } else {
            throw new IllegalArgumentException("Invalid PEM file");
        }

        // Remove header and footer
        final String contents = pemContent
                .replace(asciiArmoredType.getHeader(), "")
                .replace(asciiArmoredType.getFooter(), "")
                .trim()
                .replaceAll("\\s", "");
        return new AsciiArmoredFile(contents, asciiArmoredType);
    }

    /**
     * Writes a private key to a Ascii file.
     *
     * @param path       The location of the file to write to
     * @param privateKey The private key to write
     * @throws IOException In case of file writing error
     */
    public static void writeKey(@NonNull final Path path, @NonNull final BlsPrivateKey privateKey) throws IOException {
        writeKey(
                path,
                Base64.getEncoder()
                        .encodeToString(Objects.requireNonNull(privateKey, "key must not be null")
                                .toBytes()),
                PRIVATE_KEY);
    }

    /**
     * Writes a public key to a Ascii armored file.
     *
     * @param path      The location of the file to write to
     * @param publicKey The public key to write
     * @throws IOException In case of file writing error
     */
    public static void writeKey(@NonNull final Path path, @NonNull final BlsPublicKey publicKey) throws IOException {
        writeKey(
                path,
                Base64.getEncoder()
                        .encodeToString(Objects.requireNonNull(publicKey, "key must not be null")
                                .toBytes()),
                AsciiArmoredType.PUBLIC_KEY);
    }

    /**
     * Writes the content in an ASCII armored file.
     *
     * @param path    The location of the file in the fileSystem
     * @param content The content to write to the file
     * @param asciiArmoredType eiter "PUBLIC KEY" or "PRIVATE KEY" string
     * @throws IOException In case of file reading error
     */
    private static void writeKey(
            @NonNull final Path path, @NonNull final String content, @NonNull final AsciiArmoredType asciiArmoredType)
            throws IOException {
        Objects.requireNonNull(asciiArmoredType, "pemType must not be null");
        final String pemContent = asciiArmoredType.getHeader()
                + formatPemContent(Objects.requireNonNull(content, "content must not be null"))
                + asciiArmoredType.getFooter();

        Files.write(
                Objects.requireNonNull(path, "path must not be null"),
                pemContent.getBytes(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
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
