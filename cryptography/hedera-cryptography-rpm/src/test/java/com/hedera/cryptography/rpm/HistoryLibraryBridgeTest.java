// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.hints.AggregationAndVerificationKeys;
import com.hedera.cryptography.hints.HintsLibraryBridge;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled(
        "Requires JNI implementation for HistoryLibraryBridge, which is blocked on https://github.com/hashgraph/hedera-cryptography/pull/245")
public class HistoryLibraryBridgeTest {
    private static final HistoryLibraryBridge HISTORY = HistoryLibraryBridge.getInstance();
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();

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

    @Test
    void testSnarkVerificationKey() throws IOException {
        final byte[] elf = HistoryLibraryBridge.loadAddressBookRotationProgram();
        assertEquals(350036, elf.length);

        final ProvingAndVerifyingSnarkKeys keys = HISTORY.snarkVerificationKey(elf);

        // The pk is 164 MB, so we just check its size for practicality.
        assertEquals(164190655, keys.provingKey().length);

        assertArrayEquals(HistoryConstants.SNARK_VERIFYING_KEY, keys.verifyingKey());
    }

    @Test
    void testNewSchnorrKeyPair() {
        final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM);

        assertArrayEquals(HistoryConstants.SIGNING_KEY, keys.signingKey());
        assertArrayEquals(HistoryConstants.VERIFYING_KEY, keys.verifyingKey());
    }

    @Test
    void testSignSchnorr() {
        final SigningAndVerifyingSchnorrKeys keys = HISTORY.newSchnorrKeyPair(HistoryConstants.RANDOM);
        final byte[] signature = HISTORY.signSchnorr(HistoryConstants.MESSAGE, keys.signingKey());

        assertArrayEquals(HistoryConstants.SIGNATURE, signature);
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
    void testHashAddressBook() {
        final AddressBook addressBook = buildAddressBook(4);
        final byte[] hash = HISTORY.hashAddressBook(addressBook.verifyingKeys(), addressBook.weights());

        assertArrayEquals(HistoryConstants.ADDRESS_BOOK_HASH, hash);
    }

    @Test
    void testHashHintsVerificationKey() {
        // It's a simple SHA256 hasher, so we can hash anything. Let's hash the RANDOM:
        final byte[] hash = HISTORY.hashHintsVerificationKey(HistoryConstants.RANDOM);
        assertArrayEquals(HistoryConstants.RANDOM_HINTS_VERIFICATION_KEY_HASH, hash);
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

        final byte[] crs = HINTS.initCRS(SIGNERS_NUM);

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
        assertEquals(1477326, proof.length);

        // NOTE: computing the proof takes some 3 minutes on a MacBook Pro,
        // and may take even longer on a less powerful system. So we might as well
        // test the fast verifyChainOfTrust() method here instead of
        // having to recompute the same proof again.
        assertTrue(HISTORY.verifyChainOfTrust(snarkKeys.verifyingKey(), proof));

        // Some random modifications to invalidate the proof
        proof[0]--;
        proof[1]++;
        proof[20]--;

        assertFalse(HISTORY.verifyChainOfTrust(snarkKeys.verifyingKey(), proof));
    }
}
