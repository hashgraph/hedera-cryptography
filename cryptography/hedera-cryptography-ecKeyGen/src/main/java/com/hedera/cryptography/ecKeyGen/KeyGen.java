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

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Key generation tool
 */
public class KeyGen {

    private static final KeysGenerationService KEYS_SERVICE = new KeysGenerationService(
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.GROUP1_FOR_SIGNING),
            new NativeKeyGenerator().initialize());

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("--help")) {
            printHelp();
        } else if (args[0].equals("generate-keys") && args.length == 3) {
            String[] keyPair = KEYS_SERVICE.generateBase64KeyPair();
            if (Files.exists(Path.of(args[1]))) {
                System.err.printf("The private key file already exists. Won't overwrite. Please delete %s %n", args[1]);
            }
            if (Files.exists(Path.of(args[2]))) {
                System.err.printf("The public key file already exists. Won't overwrite. Please delete %s %n", args[2]);
            }
            Path skPath = PemFiles.pemWrite(args[1], keyPair[0], "PRIVATE KEY");
            Path pkPath = PemFiles.pemWrite(args[2], keyPair[1], "PUBLIC KEY");
            System.out.printf("Saved private and public key files into: %s and %s %n", skPath, pkPath);
        } else if (args[0].equals("generate-public-key") && args.length == 3) {
            if (!Files.exists(Path.of(args[1]))) {
                System.err.printf("The private key file does not exists. %s %n", args[1]);
            }
            if (Files.exists(Path.of(args[2]))) {
                System.err.printf("The public key file already exists. Won't overwrite. Please delete %s %n", args[2]);
            }
            String base64PrivateKey = PemFiles.pemRead(args[1], "PRIVATE KEY");
            String publicKey = KEYS_SERVICE.generateBase64KPublicKey(base64PrivateKey);
            Path pkPath = PemFiles.pemWrite(args[2], publicKey, "PUBLIC KEY");
            System.out.printf("Saved public key file into: %s %n", pkPath);
        } else {
            System.out.println("Invalid command or arguments. Use --help for usage information.");
        }
    }

    private static void printHelp() {
        System.out.println("Usage:");
        System.out.println("  --help                           Print this help message.");
        System.out.println("  generate-keys <private-key-pem> <public-key-pem>");
        System.out.println(
                "                                   Generate a private and public key pair and save them to the specified locations.");
        System.out.println("  generate-public-key <private-key-pem> <public-key-pem>");
        System.out.println(
                "                                   Generate a public key from a given private key PEM file and save it to the specified location.");
    }
}
