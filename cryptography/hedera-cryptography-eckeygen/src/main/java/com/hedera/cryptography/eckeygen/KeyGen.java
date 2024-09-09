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

import com.hedera.cryptography.eckeygen.PemFiles.PemType;
import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Key generation tool
 *
 *<p>Usage:
 *
 * <p>Display usage information:
 *
 * <pre>{@code  --help}</pre>
 *
 * <p>Generating a Key Pair:
 * <pre>{@code generate-keys path/to/privateKey.pem path/to/publicKey.pem}</pre>
 *
 * <p>Generating a Public Key from an Existing Private Key:
 *
 * <pre>{@code generate-public-key path/to/privateKey.pem path/to/publicKey.pem}</pre>
 */
public class KeyGen {

    /**
     * Empty method for static helper class
     */
    private KeyGen() {
        // Empty method for static helper class
    }

    private static final KeysGenerationService KEYS_SERVICE = new KeysGenerationService(
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES),
            NativeKeyGenerator.getInstance());

    /**
     *  <p>Usage:
     *
     *   <p>Display usage information:
     *
     *   <pre>{@code  --help}</pre>
     *
     *   <p>Generating a Key Pair:
     *   <pre>{@code generate-keys path/to/privateKey.pem path/to/publicKey.pem}</pre>
     *
     *   <p>Generating a Public Key from an Existing Private Key:
     *
     *   <pre>{@code generate-public-key path/to/privateKey.pem path/to/publicKey.pem}</pre>
     * @param args depending on the command see examples above
     * @throws Exception if something happened while generating the keys
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printHelp();
            System.exit(0);
        }

        final String commandName = args[0];
        if (commandName.equals("--help") || args.length != 3) {
            printHelp();
        }

        final String privateKeyLocation = args[1];
        final Path privateKeyPath = Path.of(privateKeyLocation);
        final String publicKeyLocation = args[2];
        final Path publicKeyPath = Path.of(publicKeyLocation);
        if (commandName.equals("generate-keys")) {
            String[] keyPair = KEYS_SERVICE.generateBase64KeyPair();
            if (Files.exists(privateKeyPath)) {
                System.err.printf(
                        "The private key file already exists. Won't overwrite. Please delete %s %n",
                        privateKeyLocation);
            }
            if (Files.exists(publicKeyPath)) {
                System.err.printf(
                        "The public key file already exists. Won't overwrite. Please delete %s %n", publicKeyLocation);
            }
            Path skPath = PemFiles.pemWrite(privateKeyLocation, keyPair[0], PemType.PRIVATE_KEY);
            Path pkPath = PemFiles.pemWrite(publicKeyLocation, keyPair[1], PemType.PUBLIC_KEY);
            System.out.printf("Saved private and public key files into: %s and %s %n", skPath, pkPath);
        } else if (commandName.equals("generate-public-key")) {
            if (!Files.exists(privateKeyPath)) {
                System.err.printf("The private key file does not exists. %s %n", privateKeyLocation);
            }
            if (Files.exists(publicKeyPath)) {
                System.err.printf(
                        "The public key file already exists. Won't overwrite. Please delete %s %n", publicKeyLocation);
            }
            String base64PrivateKey = PemFiles.pemRead(privateKeyLocation, PemType.PRIVATE_KEY);
            String publicKey = KEYS_SERVICE.generateBase64KPublicKey(base64PrivateKey);
            Path pkPath = PemFiles.pemWrite(publicKeyLocation, publicKey, PemType.PUBLIC_KEY);
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
