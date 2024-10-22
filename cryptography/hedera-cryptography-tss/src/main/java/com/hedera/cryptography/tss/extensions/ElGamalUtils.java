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

package com.hedera.cryptography.tss.extensions;

import com.hedera.cryptography.bls.BlsPrivateKey;
import com.hedera.cryptography.bls.BlsPublicKey;
import com.hedera.cryptography.bls.SignatureSchema;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A utility class for performing ElGamal encryption and decryption operations.
 *
 * <p>This class provides methods to create ElGamal-encrypted ciphertext chunks and decrypt them using preprocessed substitution tables.
 * It also provides utility methods for generating these substitution tables for encryption and decryption.
 */
public class ElGamalUtils {

    /**
     * Creates an ElGamal ciphertext from a {@code byte[]} value, chunking it byte by byte, and encrypting each chunk.
     *
     * <p>The method divides the input {@code value} into byte-sized chunks, then encrypts each chunk using the
     * provided {@code encryptionPublicKey}, the preprocessed {@code elGamalDirectSubstitutionTable}, and the
     * provided {@code randomness}.
     *
     *
     * @param encryptionPublicKey the public key used for encryption
     * @param elGamalDirectSubstitutionTable a preprocessed substitution table mapping byte values to {@link FieldElement} values
     * @param randomness a list of random {@link FieldElement} used for ciphertext generation
     * @param value the byte array to encrypt
     * @return a list of {@link GroupElement} representing the encrypted ciphertext chunks
     * @throws IllegalArgumentException if the size of {@code randomness} does not match the length of the {@code value}
     * @implNote Its responsibility of the caller setting up a valid and compatible elGamalDirectSubstitutionTable and reverseSubstitution table in each operation,
     * being the easiest way to call  {@link ElGamalUtils#elGamalSubstitutionTable(SignatureSchema)}
     * or {@link ElGamalUtils#elGamalReverseSubstitutionTable(SignatureSchema)}
     */
    @NonNull
    public static List<GroupElement> createCipherText(
            @NonNull final BlsPublicKey encryptionPublicKey,
            @NonNull final Map<Byte, FieldElement> elGamalDirectSubstitutionTable,
            @NonNull final List<FieldElement> randomness,
            @NonNull final byte[] value) {

        if (randomness.isEmpty() || randomness.size() != value.length) {
            throw new IllegalArgumentException("Invalid randomness size");
        }

        final GroupElement encryptionPublicKeyElement = encryptionPublicKey.element();
        final Group group = encryptionPublicKeyElement.getGroup();
        final GroupElement generator = group.generator();

        final List<GroupElement> encryptedShareElements = new ArrayList<>();
        for (int i = 0; i < value.length; i++) {
            final FieldElement r_j = randomness.get(i);
            final FieldElement m_j = elGamalDirectSubstitutionTable.get(value[i]);
            final GroupElement c2_j = encryptionPublicKeyElement.multiply(r_j).add(generator.multiply(m_j));
            encryptedShareElements.add(c2_j);
        }

        return encryptedShareElements;
    }

    /**
     * Decrypts a list of ElGamal-encrypted ciphertext chunks to recover the original byte array value using brute force.
     *<p>
     * In cases input parameters not matching the ones that produced the encrypted values, or dishonest decryption attempt,
     * this method will either provide an invalid byte[] as result or return null, with no guarantees of which.
     * <p>
     * <p><strong>Note:</strong> It is the responsibility of the caller to ensure compatibility between curve and groups.
     * All elements must belong to the same configuration.
     *
     * @param decryptionPrivateKey the private key used for decryption
     * @param cipherTextElements the list of {@link GroupElement} representing the ciphertext chunks to decrypt
     * @param elGamalInverseSubstitutionTable the preprocessed inverse substitution table used for brute-force decryption
     * @param randomness the list of random {@link GroupElement} values used during encryption
     * @return the decrypted byte array in honest decryption attempts, no guarantees of the obtained result otherwise.
     * @throws IllegalArgumentException if the size of {@code randomness} does not match the size of {@code cipherTextElements}
     * @throws NullPointerException if any of the parameters is null
     * @implNote This method performs decryption by using the {@code decryptionPrivateKey} and the preprocessed {@code elGamalInverseSubstitutionTable}
     * to convert each encrypted chunk back to its original value. It uses the provided {@code randomness} to unmask each ciphertext chunk
     * during the process. <p>Its responsibility of the caller setting up a valid and compatible elGamalDirectSubstitutionTable and reverseSubstitution table in each operation,
     * being the easiest way to call {@link ElGamalUtils#elGamalSubstitutionTable(SignatureSchema)} or {@link ElGamalUtils#elGamalReverseSubstitutionTable(SignatureSchema)}
     */
    @Nullable
    public static byte[] readCipherText(
            @NonNull final BlsPrivateKey decryptionPrivateKey,
            @NonNull final List<GroupElement> randomness,
            @NonNull final Map<GroupElement, Byte> elGamalInverseSubstitutionTable,
            @NonNull final List<GroupElement> cipherTextElements) {

        Objects.requireNonNull(decryptionPrivateKey, "decryptionPrivateKey must not be null");
        if (Objects.requireNonNull(randomness, "randomness must not be null").size()
                != Objects.requireNonNull(cipherTextElements, "cipherTextElements must not be null")
                        .size()) {
            throw new IllegalArgumentException("Mismatched randomness and ciphertext size");
        }
        Objects.requireNonNull(elGamalInverseSubstitutionTable, "elGamalInverseSubstitutionTable must not be null");

        final FieldElement keyElement = decryptionPrivateKey.element();
        final Field keyField = keyElement.getField();

        final FieldElement zeroElement = keyField.fromLong(0L);

        final byte[] output = new byte[cipherTextElements.size()];
        for (int i = 0; i < cipherTextElements.size(); i++) {
            final GroupElement chunkCiphertext = cipherTextElements.get(i);
            final GroupElement chunkRandomness = randomness.get(i);
            final GroupElement antiMask = chunkRandomness.multiply(zeroElement.subtract(keyElement));
            final GroupElement commitment = chunkCiphertext.add(antiMask);

            Byte value = elGamalInverseSubstitutionTable.get(commitment);
            if (value == null) {
                return null;
            }
            output[i] = value;
        }

        return output;
    }

    /**
     * Generates an inverse substitution table used to map a {@link GroupElement} to its corresponding byte value.
     *
     * <p>This map is used during decryption to obtain the original byte value from a group element generated by multiplying
     * the group generator by the byte value.
     *
     * @param signatureSchema the {@link SignatureSchema} defining the group and field elements used in ElGamal encryption
     * @return a map of {@link GroupElement} to byte values used for decryption
     */
    @NonNull
    public static Map<GroupElement, Byte> elGamalReverseSubstitutionTable(
            @NonNull final SignatureSchema signatureSchema) {
        final Field field = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null")
                .getPairingFriendlyCurve()
                .field();
        final Group encryptionGroup = signatureSchema.getPublicKeyGroup();
        final Map<GroupElement, Byte> elGamalInverseSubstitutionTable = new HashMap<>();

        for (byte i = Byte.MIN_VALUE; i < Byte.MAX_VALUE; i++) {
            elGamalInverseSubstitutionTable.put(encryptionGroup.generator().multiply(field.fromLong(i)), i);
        }
        elGamalInverseSubstitutionTable.put(
                encryptionGroup.generator().multiply(field.fromLong(Byte.MAX_VALUE)), Byte.MAX_VALUE);
        return elGamalInverseSubstitutionTable;
    }

    /**
     * Generates a substitution table mapping byte values to their corresponding {@link FieldElement} values.
     *
     * <p>This map is used during encryption to substitute byte values with corresponding field elements.
     *
     * @param signatureSchema the {@link SignatureSchema} defining the group and field elements used in ElGamal encryption
     * @return a map of byte values to {@link FieldElement} used for encryption
     */
    @NonNull
    public static Map<Byte, FieldElement> elGamalSubstitutionTable(@NonNull final SignatureSchema signatureSchema) {
        final Field field = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null")
                .getPairingFriendlyCurve()
                .field();
        return IntStream.rangeClosed(Byte.MIN_VALUE, Byte.MAX_VALUE)
                .boxed()
                .collect(Collectors.toMap(i -> (byte) (int) i, i -> field.fromLong(i)));
    }

    /**
     * Generates randomness consisting of length number of {@link FieldElement}s
     *
     * @param random a source of randomness
     * @param length The length of the resulting list
     * @param signatureSchema the {@link SignatureSchema} defining the group and field elements used in ElGamal
     *                        encryption
     * @return a list of random field elements
     */
    @NonNull
    // FUTURE - TSS (Maybe move somewhere else)
    public static List<FieldElement> generateEntropy(
            @NonNull final Random random, final int length, @NonNull final SignatureSchema signatureSchema) {
        Objects.requireNonNull(random, "random must not be null");
        final Field field = Objects.requireNonNull(signatureSchema, "signatureSchema must not be null")
                .getPairingFriendlyCurve()
                .field();
        return IntStream.range(0, length).boxed().map(i -> field.random(random)).toList();
    }
}
