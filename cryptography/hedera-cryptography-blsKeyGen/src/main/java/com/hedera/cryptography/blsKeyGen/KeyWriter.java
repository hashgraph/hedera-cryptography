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

import com.hedera.common.nativesupport.LibraryLoader;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class KeyWriter {

    public static void main(String[] args) {

        LibraryLoader.create(BlsKeyGen.class).install("libkey_gen");

        String[] keyPair = new String[2];
        if (new BlsKeyGen()
                        .generateKeyPair(
                                SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.GROUP1_FOR_SIGNING)
                                        .getIdByte(),
                                keyPair)
                != 0) throw new RuntimeException("Failed to generate keys");
        String base64PrivateKey = keyPair[0];
        String base64PublicKey = keyPair[1];

        try {
            Path sk = writePemFile(base64PrivateKey, "PRIVATE KEY", "private_key.pem");
            Path pk = writePemFile(base64PublicKey, "PUBLIC KEY", "public_key.pem");
            System.out.printf(
                    "Keys have been written to PEM files successfully. privateKey:%s publicKey:%s\n",
                    sk.toAbsolutePath(), pk.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error writing keys to PEM files: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static Path writePemFile(String base64Key, String keyType, String fileName) throws IOException {
        String header = "-----BEGIN " + keyType + "-----\n";
        String footer = "\n-----END " + keyType + "-----\n";
        String content = formatPemContent(base64Key);

        String pemContent = header + content + footer;

        Files.write(
                Path.of(fileName),
                pemContent.getBytes(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
        return Path.of(fileName);
    }

    private static String formatPemContent(String base64) {
        // Insert line breaks every 64 characters to conform with PEM format standards
        StringBuilder builder = new StringBuilder();
        int index = 0;
        while (index < base64.length()) {
            builder.append(base64, index, Math.min(index + 64, base64.length()));
            builder.append("\n");
            index += 64;
        }
        return builder.toString();
    }
}
