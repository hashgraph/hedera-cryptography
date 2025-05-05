// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.hints.AggregationAndVerificationKeys;
import com.hedera.cryptography.hints.HintsLibraryBridge;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class HistoryLibraryBridgeTest {
    private static final HistoryLibraryBridge HISTORY = HistoryLibraryBridge.getInstance();
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();

    private static final byte[] EMPTY = new byte[0];

    // We use ABs with 4 and 5 entries, so 8 should be good.
    private static final int SIGNERS_NUM = 8;

    // ------------------------------------------------------------------------
    // Modeling the Address Book
    // ------------------------------------------------------------------------
    private static record Address(byte[] verifyingKey, long weight) {
        static Address fromRandom(byte[] random, long weight) {
            final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(random);
            return new Address(keys.verifyingKey(), weight);
        }
    }

    private static record AddressBook(List<Address> addresses) {
        byte[][] verifyingKeys() {
            return addresses.stream().map(Address::verifyingKey).toArray(size -> new byte[size][]);
        }

        long[] weights() {
            return addresses.stream().mapToLong(Address::weight).toArray();
        }
    }

    /**
     * Build an address book with up to 5 addresses using RANDOM_0 through RANDOM_3, and RANDOM
     * constants as seeds for generating Schnorr keys. The weights are hard-coded in this method.
     * @param num the number of addresses in the address book
     * @return an address book
     */
    private AddressBook buildAddressBook(final int num) {
        return new AddressBook(List.of(
                        Address.fromRandom(HistoryConstants.RANDOM_0, 111),
                        Address.fromRandom(HistoryConstants.RANDOM_1, 222),
                        Address.fromRandom(HistoryConstants.RANDOM_2, 1),
                        Address.fromRandom(HistoryConstants.RANDOM_3, 999),
                        Address.fromRandom(HistoryConstants.RANDOM, 555))
                .subList(0, num));
    }
    // ------------------------------------------------------------------------
    // Finished modeling the Address Book
    // ------------------------------------------------------------------------

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    private void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @Test
    void testSnarkVerificationKey() throws IOException {
        final byte[] elf = HistoryLibraryBridge.loadAddressBookRotationProgram();
        assertEquals(352504, elf.length);

        final ProvingAndVerifyingSnarkKeys keys = HISTORY.snarkVerificationKey(elf);

        // The pk is 164 MB, so we just check its size for practicality.
        assertEquals(164194426, keys.provingKey().length);

        assertArrayEquals(HistoryConstants.SNARK_VERIFYING_KEY, keys.verifyingKey());
    }

    @Test
    void testSnarkVerificationKeyConstraints() throws IOException {
        assertNull(HISTORY.snarkVerificationKey(null));

        final byte[] elf = HistoryLibraryBridge.loadAddressBookRotationProgram();

        // Corrupt the ELF a bit at a random location. Note that if the binary elf is replaced,
        // the location index may or may not need changing.
        elf[3579]++;
        final ProvingAndVerifyingSnarkKeys keys = HISTORY.snarkVerificationKey(elf);
        // The pk size is still the same as with a good ELF, but the verifyingKey is different
        assertEquals(164194426, keys.provingKey().length);
        assertFalse(Arrays.equals(HistoryConstants.SNARK_VERIFYING_KEY, keys.verifyingKey()));

        // If we corrupt the ELF a lot, then a panic occurs. So this is as far as we can test this.
    }

    @Test
    void testNewSchnorrKeyPair() {
        final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM);

        assertArrayEquals(HistoryConstants.SIGNING_KEY, keys.signingKey());
        assertArrayEquals(HistoryConstants.VERIFYING_KEY, keys.verifyingKey());
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 1, 16, 31, 33, 128})
    void testNewSchnorrKeyConstraints(final int length) {
        assertNull(HISTORY.newSchnorrKeyPair(length == -1 ? null : new byte[length]));
    }

    @Test
    void testSignSchnorr() {
        final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM);
        final byte[] signature = HISTORY.signSchnorr(HistoryConstants.MESSAGE, keys.signingKey());

        assertArrayEquals(HistoryConstants.SIGNATURE, signature);
    }

    @Test
    void testSignSchnorrConstraints() {
        final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM);

        assertNull(HISTORY.signSchnorr(null, keys.signingKey()));
        assertArrayEquals(HistoryConstants.EMPTY_MESSAGE_SIGNATURE, HISTORY.signSchnorr(EMPTY, keys.signingKey()));
        assertNull(HISTORY.signSchnorr(HistoryConstants.MESSAGE, null));
        assertNull(HISTORY.signSchnorr(HistoryConstants.MESSAGE, EMPTY));

        // Try corrupting the key
        keys.signingKey()[0]++;
        final byte[] signature = HISTORY.signSchnorr(HistoryConstants.MESSAGE, keys.signingKey());
        assertNotNull(signature);
        assertFalse(Arrays.equals(HistoryConstants.SIGNATURE, signature));

        // The message could be anything, and the key is just a number, so it can be anything too,
        // so this is as far as we can test this.
    }

    @Test
    void testVerifySchnorr() {
        final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM);
        final byte[] signature = HISTORY.signSchnorr(HistoryConstants.MESSAGE, keys.signingKey());

        assertTrue(HISTORY.verifySchnorr(signature, HistoryConstants.MESSAGE, keys.verifyingKey()));

        // Just some random modifications to make the signature invalid
        signature[0]++;
        signature[1]--;
        signature[10]++;

        assertFalse(HISTORY.verifySchnorr(signature, HistoryConstants.MESSAGE, keys.verifyingKey()));
    }

    @Test
    void testVerifySchnorrConstraints() {
        final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM);
        final byte[] signature = HISTORY.signSchnorr(HistoryConstants.MESSAGE, keys.signingKey());

        assertFalse(HISTORY.verifySchnorr(null, HistoryConstants.MESSAGE, keys.verifyingKey()));
        assertFalse(HISTORY.verifySchnorr(EMPTY, HistoryConstants.MESSAGE, keys.verifyingKey()));
        assertFalse(HISTORY.verifySchnorr(signature, null, keys.verifyingKey()));
        assertFalse(HISTORY.verifySchnorr(signature, EMPTY, keys.verifyingKey()));
        assertFalse(HISTORY.verifySchnorr(signature, HistoryConstants.MESSAGE, null));
        assertFalse(HISTORY.verifySchnorr(signature, HistoryConstants.MESSAGE, EMPTY));
    }

    @Test
    void testHashAddressBook() {
        final AddressBook addressBook = buildAddressBook(4);
        final byte[] hash = HISTORY.hashAddressBook(addressBook.verifyingKeys(), addressBook.weights());

        assertArrayEquals(HistoryConstants.ADDRESS_BOOK_HASH, hash);
    }

    @Test
    void testHashAddressBookConstraints() {
        final AddressBook addressBook = buildAddressBook(4);

        assertNull(HISTORY.hashAddressBook(null, addressBook.weights()));
        assertNull(HISTORY.hashAddressBook(new byte[0][], addressBook.weights()));
        assertNull(HISTORY.hashAddressBook(addressBook.verifyingKeys(), null));
        assertNull(HISTORY.hashAddressBook(addressBook.verifyingKeys(), new long[0]));
        assertNull(HISTORY.hashAddressBook(
                Arrays.copyOf(addressBook.verifyingKeys(), addressBook.verifyingKeys().length - 1),
                addressBook.weights()));
        assertNull(HISTORY.hashAddressBook(
                addressBook.verifyingKeys(), Arrays.copyOf(addressBook.weights(), addressBook.weights().length - 1)));

        // Surprisingly, an empty AB produces a non-empty hash, which might be useful for edge-cases I suppose:
        assertArrayEquals(
                HistoryConstants.EMPTY_ADDRESS_BOOK_HASH, HISTORY.hashAddressBook(new byte[0][], new long[0]));
    }

    @Test
    void testHashHintsVerificationKey() {
        // It's a simple SHA256 hasher, so we can hash anything. Let's hash the RANDOM:
        final byte[] hash = HISTORY.hashHintsVerificationKey(HistoryConstants.RANDOM);
        assertArrayEquals(HistoryConstants.RANDOM_HINTS_VERIFICATION_KEY_HASH, hash);
    }

    @Test
    void testHashHintsVerificationKeyConstraints() {
        assertNull(HISTORY.hashHintsVerificationKey(null));
        // An empty input still produces a hash, which may be useful for edge-cases I suppose:
        assertArrayEquals(HistoryConstants.EMPTY_HINTS_VERIFICATION_KEY_HASH, HISTORY.hashHintsVerificationKey(EMPTY));
    }

    @Test
    void testProveChainOfTrustConstraints() throws IOException {
        final ProvingAndVerifyingSnarkKeys snarkKeys =
                HISTORY.snarkVerificationKey(HistoryLibraryBridge.loadAddressBookRotationProgram());
        final AddressBook genesisAddressBook = buildAddressBook(4);
        final byte[] genesisAddressBookHash =
                HISTORY.hashAddressBook(genesisAddressBook.verifyingKeys(), genesisAddressBook.weights());

        final AddressBook nextAddressBook = buildAddressBook(5);
        final byte[] nextAddressBookHash =
                HISTORY.hashAddressBook(nextAddressBook.verifyingKeys(), nextAddressBook.weights());

        final byte[] crs = HINTS.initCRS((short) SIGNERS_NUM);

        // partyId 0
        final byte[] secretKey0 = HINTS.generateSecretKey(HistoryConstants.RANDOM_0);
        final byte[] hints0 = HINTS.computeHints(crs, secretKey0, 0, SIGNERS_NUM);
        final SigningAndVerifyingSchnorrKeys schnorrKeys0 = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM_0);

        // partyId 1
        final byte[] secretKey1 = HINTS.generateSecretKey(HistoryConstants.RANDOM_1);
        final byte[] hints1 = HINTS.computeHints(crs, secretKey1, 1, SIGNERS_NUM);
        final SigningAndVerifyingSchnorrKeys schnorrKeys1 = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM_1);

        // partyId 2
        final byte[] secretKey2 = HINTS.generateSecretKey(HistoryConstants.RANDOM_2);
        final byte[] hints2 = HINTS.computeHints(crs, secretKey2, 2, SIGNERS_NUM);
        final SigningAndVerifyingSchnorrKeys schnorrKeys2 = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM_2);

        // partyId 3
        final byte[] secretKey3 = HINTS.generateSecretKey(HistoryConstants.RANDOM_3);
        final byte[] hints3 = HINTS.computeHints(crs, secretKey3, 3, SIGNERS_NUM);
        final SigningAndVerifyingSchnorrKeys schnorrKeys3 = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM_3);

        final AggregationAndVerificationKeys hintsKeys = HINTS.preprocess(
                crs,
                new int[] {0, 1, 2, 3},
                new byte[][] {hints0, hints1, hints2, hints3},
                genesisAddressBook.weights(),
                SIGNERS_NUM);

        final byte[] hintsVerificationKeyHash = HISTORY.hashHintsVerificationKey(hintsKeys.verificationKey());

        final byte[] message =
                HistoryLibraryBridge.formatRotationMessage(nextAddressBookHash, hintsVerificationKeyHash);
        final byte[][] signatures = new byte[][] {
            HISTORY.signSchnorr(message, schnorrKeys0.signingKey()),
            HISTORY.signSchnorr(message, schnorrKeys1.signingKey()),
            HISTORY.signSchnorr(message, schnorrKeys2.signingKey()),
            HISTORY.signSchnorr(message, schnorrKeys3.signingKey())
        };

        // Basic null/empty checks
        assertNull(HISTORY.proveChainOfTrust(
                null,
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                EMPTY,
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                null,
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                EMPTY,
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                null,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                EMPTY,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                null,
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                new byte[0][],
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                null,
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                new long[0],
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                null,
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                new byte[0][],
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                null,
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                new long[0],
                null,
                hintsVerificationKeyHash,
                signatures));
        // Note: no null test for the currentAddressBookProof because it may be null, but not empty if it's non-null!
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                EMPTY,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                null,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                EMPTY,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                null));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                new byte[0][]));

        // Array size mismatches checks
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                Arrays.copyOf(genesisAddressBook.weights(), genesisAddressBook.weights().length - 1),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                Arrays.copyOf(nextAddressBook.weights(), nextAddressBook.weights().length + 1),
                null,
                hintsVerificationKeyHash,
                signatures));
        assertNull(HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                Arrays.copyOf(signatures, signatures.length - 1)));
    }

    // This method is extracted to allow us to enhance it in the future to support computing
    // proofs for subsequent address books. For now, it only covers the basic case where
    // a genesis address book endorses a single next address book.
    private byte[] computeProof(ProvingAndVerifyingSnarkKeys snarkKeys) throws IOException {
        final AddressBook genesisAddressBook = buildAddressBook(4);
        final byte[] genesisAddressBookHash =
                HISTORY.hashAddressBook(genesisAddressBook.verifyingKeys(), genesisAddressBook.weights());

        final AddressBook nextAddressBook = buildAddressBook(5);
        final byte[] nextAddressBookHash =
                HISTORY.hashAddressBook(nextAddressBook.verifyingKeys(), nextAddressBook.weights());

        final byte[] crs = HINTS.initCRS((short) SIGNERS_NUM);

        // partyId 0
        final byte[] secretKey0 = HINTS.generateSecretKey(HistoryConstants.RANDOM_0);
        final byte[] hints0 = HINTS.computeHints(crs, secretKey0, 0, SIGNERS_NUM);
        final SigningAndVerifyingSchnorrKeys schnorrKeys0 = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM_0);

        // partyId 1
        final byte[] secretKey1 = HINTS.generateSecretKey(HistoryConstants.RANDOM_1);
        final byte[] hints1 = HINTS.computeHints(crs, secretKey1, 1, SIGNERS_NUM);
        final SigningAndVerifyingSchnorrKeys schnorrKeys1 = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM_1);

        // partyId 2
        final byte[] secretKey2 = HINTS.generateSecretKey(HistoryConstants.RANDOM_2);
        final byte[] hints2 = HINTS.computeHints(crs, secretKey2, 2, SIGNERS_NUM);

        // partyId 3
        final byte[] secretKey3 = HINTS.generateSecretKey(HistoryConstants.RANDOM_3);
        final byte[] hints3 = HINTS.computeHints(crs, secretKey3, 3, SIGNERS_NUM);
        final SigningAndVerifyingSchnorrKeys schnorrKeys3 = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM_3);

        final AggregationAndVerificationKeys hintsKeys = HINTS.preprocess(
                crs,
                new int[] {0, 1, 2, 3},
                new byte[][] {hints0, hints1, hints2, hints3},
                genesisAddressBook.weights(),
                SIGNERS_NUM);

        final byte[] hintsVerificationKeyHash = HISTORY.hashHintsVerificationKey(hintsKeys.verificationKey());

        final byte[] message =
                HistoryLibraryBridge.formatRotationMessage(nextAddressBookHash, hintsVerificationKeyHash);
        final byte[][] signatures = new byte[][] {
            HISTORY.signSchnorr(message, schnorrKeys0.signingKey()),
            HISTORY.signSchnorr(message, schnorrKeys1.signingKey()),
            // partyId 2 has the lowest weight, so its signature isn't important.
            // Pretend we never received it even and pass `null` here:
            null,
            HISTORY.signSchnorr(message, schnorrKeys3.signingKey())
        };

        final byte[] proof = HISTORY.proveChainOfTrust(
                snarkKeys.provingKey(),
                snarkKeys.verifyingKey(),
                genesisAddressBookHash,
                genesisAddressBook.verifyingKeys(),
                genesisAddressBook.weights(),
                nextAddressBook.verifyingKeys(),
                nextAddressBook.weights(),
                null,
                hintsVerificationKeyHash,
                signatures);

        return proof;
    }

    @Test
    void testProveAndVerifyChainOfTrust() throws IOException {
        final ProvingAndVerifyingSnarkKeys snarkKeys =
                HISTORY.snarkVerificationKey(HistoryLibraryBridge.loadAddressBookRotationProgram());

        final byte[] proof = computeProof(snarkKeys);

        // It's almost 1.5 MB, so we only check the length for practicality.
        // The verifyChainOfTrust() test right below will verify the actual bytes for us.
        assertEquals(1477358, proof.length);

        // NOTE: computing the proof takes some 3 minutes on a MacBook Pro,
        // and may take even longer on a less powerful system. So we might as well
        // test the fast verifyChainOfTrust() method here instead of
        // having to recompute the same proof again.
        assertTrue(HISTORY.verifyChainOfTrust(snarkKeys.verifyingKey(), proof));

        // Verify some constraints while we have this expensive proof on hand:
        assertFalse(HISTORY.verifyChainOfTrust(null, proof));
        assertFalse(HISTORY.verifyChainOfTrust(EMPTY, proof));

        // Some random modifications to invalidate the proof
        proof[0]--;
        proof[1]++;
        proof[20]--;

        assertFalse(HISTORY.verifyChainOfTrust(snarkKeys.verifyingKey(), proof));
    }

    @Test
    void testVerifyChainOfTrustConstraints() throws IOException {
        final ProvingAndVerifyingSnarkKeys snarkKeys =
                HISTORY.snarkVerificationKey(HistoryLibraryBridge.loadAddressBookRotationProgram());

        assertFalse(HISTORY.verifyChainOfTrust(snarkKeys.verifyingKey(), null));
        assertFalse(HISTORY.verifyChainOfTrust(snarkKeys.verifyingKey(), EMPTY));
    }
}
