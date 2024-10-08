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

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.signatures.api.GroupAssignment;
import com.hedera.cryptography.pairings.signatures.api.PairingKeyPair;
import com.hedera.cryptography.pairings.signatures.api.PairingPrivateKey;
import com.hedera.cryptography.pairings.signatures.api.PairingPublicKey;
import com.hedera.cryptography.pairings.signatures.api.SignatureSchema;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Key generation tool
 *
 * <p>Usage:
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
    private static final SignatureSchema SIGNATURE_SCHEMA = SignatureSchema.create(Curve.ALT_BN128,
            GroupAssignment.SHORT_SIGNATURES);

    /**
     * Empty method for static helper class
     */
    private KeyGen() {
        // Empty method for static helper class
    }

    /**
     * <p>Usage:
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
     *
     * @param args depending on the command see examples above
     * @throws Exception if something happened while generating the keys
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printHelpAndExit();
        }

        final String commandName = args[0];
        if (commandName.equals("--help") || args.length != 3) {
            printHelpAndExit();
        }

        final String privateKeyLocation = args[1];
        final Path privateKeyPath = Path.of(privateKeyLocation);
        final String publicKeyLocation = args[2];
        final Path publicKeyPath = Path.of(publicKeyLocation);
        if (commandName.equals("generate-keys")) {

            if (Files.exists(privateKeyPath)) {
                error("The private key file already exists. Won't overwrite. Please delete %s %n",
                        privateKeyLocation);
            }
            if (Files.exists(publicKeyPath)) {
                error("The public key file already exists. Won't overwrite. Please delete %s %n", publicKeyLocation);
            }
            final PairingKeyPair keyPair = generateKeyPair();
            Path skPath = PemFiles.writeKey(privateKeyLocation, keyPair.privateKey());
            Path pkPath = PemFiles.writeKey(publicKeyLocation, keyPair.publicKey());
            System.out.printf("Saved private and public key files into: %s and %s %n", skPath, pkPath);
        } else if (commandName.equals("generate-public-key")) {
            if (!Files.exists(privateKeyPath)) {
                error("The private key file does not exists. %s %n", privateKeyLocation);
            }
            if (Files.exists(publicKeyPath)) {
                error("The public key file already exists. Won't overwrite. Please delete %s %n", publicKeyLocation);
            }
            final PairingPrivateKey privateKey = PemFiles.readPrivateKey(privateKeyLocation);
            final PairingPublicKey publicKey = privateKey.createPublicKey();
            Path pkPath = PemFiles.writeKey(publicKeyLocation, publicKey);
            System.out.printf("Saved public key file into: %s %n", pkPath);
        } else {
            System.out.println("Invalid command or arguments. Use --help for usage information.");
        }
    }

    /**
     * Prints an error message and exits
     *
     * @param message     the error message
     * @param messageArgs the message arguments
     */
    private static void error(@NonNull final String message, @NonNull final Object... messageArgs) {
        System.err.printf(message, messageArgs);
        System.exit(1);

    }

    /**
     * Prints the help message and exits
     */
    private static void printHelpAndExit() {
        System.out.println(
                """
                        Usage:
                          --help                           Print this help message.
                          generate-keys <private-key-pem> <public-key-pem>
                                                           Generate a private and public key pair and save them to the specified locations.
                          generate-public-key <private-key-pem> <public-key-pem>
                                                           Generate a public key from a given private key PEM file and save it to the specified location.
                        """);
        System.exit(0);
    }

    /**
     * Generates a Key Pair (private and public keys)
     *
     * @return a key pair
     * @throws NoSuchAlgorithmException if no algorithm found to get a {@link SecureRandom} instance
     */
    public static PairingKeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final PairingPrivateKey pairingPrivateKey =
                PairingPrivateKey.create(SIGNATURE_SCHEMA, SecureRandom.getInstanceStrong());
        return new PairingKeyPair(pairingPrivateKey, pairingPrivateKey.createPublicKey());
    }
}
