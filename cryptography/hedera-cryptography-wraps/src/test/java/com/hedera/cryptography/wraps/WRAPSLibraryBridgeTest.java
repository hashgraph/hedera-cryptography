// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.hints.AggregationAndVerificationKeys;
import com.hedera.cryptography.hints.HintsLibraryBridge;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class WRAPSLibraryBridgeTest {
    private static final WRAPSLibraryBridge WRAPS = WRAPSLibraryBridge.getInstance();
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();
    private static final byte[][] EMPTY_BYTE_ARRAY_2 = new byte[0][];

    // We use ABs with 4 and 5 entries, so 8 should be good.
    private static final int SIGNERS_NUM = 8;

    private static final byte[] CRS = HINTS.initCRS((short) SIGNERS_NUM);

    private record Node(byte[] seed, SchnorrKeys schnorrKeys, long weight, byte[] hintsSecretKey, byte[] hints) {
        static Node from(byte[] seed, long weight, int partyId) {
            final byte[] hintsSecretKey = HINTS.generateSecretKey(seed);
            return new Node(
                    seed,
                    WRAPS.generateSchnorrKeys(seed),
                    weight,
                    hintsSecretKey,
                    HINTS.computeHints(CRS, hintsSecretKey, partyId, SIGNERS_NUM));
        }
    }

    private record Network(List<Node> nodes) {
        byte[][] publicKeys() {
            return listToArray(
                    nodes.stream().map(n -> n.schnorrKeys().publicKey()).toList());
        }

        long[] weights() {
            return nodes.stream().mapToLong(Node::weight).toArray();
        }
    }

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    public static void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @Test
    public void testGenerateSchnorrKeys() {
        final SchnorrKeys schnorrKeys = WRAPS.generateSchnorrKeys(Constants.SEED_0);

        assertArrayEquals(Constants.SCHNORR_PRIVATE_KEY_0, schnorrKeys.privateKey());
        assertArrayEquals(Constants.SCHNORR_PUBLIC_KEY_0, schnorrKeys.publicKey());

        // Verify if a different seed generates different keys:
        final SchnorrKeys keys1 = WRAPS.generateSchnorrKeys(Constants.SEED_1);
        assertFalse(Arrays.equals(keys1.privateKey(), schnorrKeys.privateKey()));
        assertFalse(Arrays.equals(keys1.publicKey(), schnorrKeys.publicKey()));
    }

    @Test
    public void testGenerateSchnorrKeysConstraints() {
        assertEquals(null, WRAPS.generateSchnorrKeys(null));
        assertEquals(null, WRAPS.generateSchnorrKeys(new byte[0]));

        // length less than ENTROPY_SIZE:
        assertEquals(null, WRAPS.generateSchnorrKeys(new byte[] {1, 2, 3}));

        // length greater than ENTROPY_SIZE:
        byte[] tooLargeArray = new byte[WRAPSLibraryBridge.ENTROPY_SIZE + 3];
        assertEquals(null, WRAPS.generateSchnorrKeys(tooLargeArray));
    }

    private static byte[][] listToArray(List<byte[]> list) {
        return list.toArray(new byte[list.size()][]);
    }

    private record SigningProtocolOutput(byte[] signature, List<List<byte[]>> roundMessages) {}

    private SigningProtocolOutput aggregateSignature(final Network network, final byte[] message) {
        final List<byte[]> round1 = network.nodes().stream()
                .map(node -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R1,
                        node.seed(),
                        message,
                        node.schnorrKeys().privateKey(),
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2))
                .toList();
        final byte[][] round1Array = listToArray(round1);

        final List<byte[]> round2 = network.nodes().stream()
                .map(node -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R2,
                        node.seed(),
                        message,
                        node.schnorrKeys().privateKey(),
                        network.publicKeys(),
                        round1Array,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2))
                .toList();
        final byte[][] round2Array = listToArray(round2);

        final List<byte[]> round3 = network.nodes().stream()
                .map(node -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R3,
                        node.seed(),
                        message,
                        node.schnorrKeys().privateKey(),
                        network.publicKeys(),
                        round1Array,
                        round2Array,
                        EMPTY_BYTE_ARRAY_2))
                .toList();
        final byte[][] round3Array = listToArray(round3);

        final byte[] signature = WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                network.publicKeys(),
                round1Array,
                round2Array,
                round3Array);

        return new SigningProtocolOutput(signature, List.of(round1, round2, round3));
    }

    @Test
    public void testRunSigningProtocolPhaseAndVerifySignature() {
        final Network network = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2)));

        final SigningProtocolOutput output = aggregateSignature(network, Constants.MESSAGE_0);
        for (int roundIndex = 0; roundIndex < 3; roundIndex++) {
            for (int i = 0; i < output.roundMessages().get(roundIndex).size(); i++) {
                assertArrayEquals(
                        Constants.ROUND_MESSAGES[roundIndex][i],
                        output.roundMessages().get(roundIndex).get(i));
            }
        }

        assertArrayEquals(Constants.SIGNATURE, output.signature());

        // Let's also verify the signature while we're at it, so that we don't duplicate the code above:
        assertTrue(WRAPS.verifySignature(network.publicKeys(), Constants.MESSAGE_0, output.signature()));
        network.publicKeys()[0][20]++;
        assertFalse(WRAPS.verifySignature(network.publicKeys(), Constants.MESSAGE_0, output.signature()));
        network.publicKeys()[0][20]--;
        assertFalse(WRAPS.verifySignature(network.publicKeys(), Constants.MESSAGE_1, output.signature()));
        output.signature()[7]++;
        assertFalse(WRAPS.verifySignature(network.publicKeys(), Constants.MESSAGE_0, output.signature()));
        output.signature()[7]--;

        // And while we're at it, let's test verifySignature constraints
        assertFalse(WRAPS.verifySignature(null, Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(EMPTY_BYTE_ARRAY_2, Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(network.publicKeys(), null, output.signature()));
        assertFalse(WRAPS.verifySignature(network.publicKeys(), new byte[0], output.signature()));
        assertFalse(WRAPS.verifySignature(network.publicKeys(), Constants.MESSAGE_0, null));
        assertFalse(WRAPS.verifySignature(network.publicKeys(), Constants.MESSAGE_0, new byte[0]));
        assertFalse(WRAPS.verifySignature(
                new byte[][] {network.publicKeys()[0], null}, Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(
                new byte[][] {network.publicKeys()[0], new byte[0]}, Constants.MESSAGE_0, output.signature()));
    }

    @Test
    public void testRunSigningProtocolPhaseConstraints() {
        final Network network = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2)));

        final Node node = network.nodes().get(0);
        final byte[] message = Constants.MESSAGE_0;

        assertNull(WRAPS.runSigningProtocolPhase(
                null,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                null,
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                new byte[0],
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                new byte[] {1},
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                null,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                null,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                new byte[0],
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}}));

        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                null,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                null,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}}));

        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {null},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));

        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                node.seed(),
                message,
                null,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {null},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}}));
    }

    @Test
    public void testHashAddressBook() {
        final List<SchnorrKeys> keys = List.of(Constants.SEED_0, Constants.SEED_1, Constants.SEED_2).stream()
                .map(WRAPS::generateSchnorrKeys)
                .toList();
        final byte[][] schnorrPublicKeys =
                listToArray(keys.stream().map(SchnorrKeys::publicKey).toList());

        assertArrayEquals(Constants.HASH_0, WRAPS.hashAddressBook(schnorrPublicKeys, new long[] {1000, 0, 100}));

        assertArrayEquals(Constants.HASH_1, WRAPS.hashAddressBook(schnorrPublicKeys, new long[] {1001, 0, 100}));

        byte[] temp = schnorrPublicKeys[0];
        schnorrPublicKeys[0] = schnorrPublicKeys[1];
        schnorrPublicKeys[1] = temp;
        assertArrayEquals(Constants.HASH_2, WRAPS.hashAddressBook(schnorrPublicKeys, new long[] {1001, 0, 100}));
    }

    @Test
    public void testHashAddressBookConstraints() {
        final SchnorrKeys schnorrKeys = WRAPS.generateSchnorrKeys(Constants.SEED_0);

        assertNull(WRAPS.hashAddressBook(null, new long[] {1000, 0, 100}));
        assertNull(WRAPS.hashAddressBook(new byte[0][], null));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), schnorrKeys.publicKey()}, new long[] {1000, 0, 100}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), schnorrKeys.publicKey(), schnorrKeys.publicKey()},
                new long[] {1000, -1, 100}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), schnorrKeys.publicKey(), schnorrKeys.publicKey()},
                new long[] {Long.MAX_VALUE, 0, 100}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), null, schnorrKeys.publicKey()}, new long[] {1000, 0, 100}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), new byte[0], schnorrKeys.publicKey()},
                new long[] {1000, 0, 100}));

        // Native code supports up to MAX_AB_SIZE = 128 (as of 10/20/2025), so let's try 128 and 129:
        // This should succeed (aka return non-null):
        final int maxAllowedNum = 128;
        assertNotNull(WRAPS.hashAddressBook(
                listToArray(IntStream.range(0, maxAllowedNum)
                        .mapToObj(i -> schnorrKeys.publicKey())
                        .toList()),
                new long[maxAllowedNum]));
        // Now do the same but exceed the max allowed size, and this should fail (return null):
        final int tooBigNum = maxAllowedNum + 1;
        assertNull(WRAPS.hashAddressBook(
                listToArray(IntStream.range(0, tooBigNum)
                        .mapToObj(i -> schnorrKeys.publicKey())
                        .toList()),
                new long[tooBigNum]));
    }

    @Test
    public void testFormatRotationMessageConstraints() {
        final byte[][] keys = new byte[][] {new byte[] {1}, new byte[] {2}, new byte[] {3}};
        final long[] weights = new long[] {1, 2, 3};
        final byte[] hintsKey = new byte[1288];

        assertNull(WRAPS.formatRotationMessage(null, weights, hintsKey));
        assertNull(WRAPS.formatRotationMessage(new byte[0][], weights, hintsKey));
        assertNull(WRAPS.formatRotationMessage(new byte[][] {null, keys[1], keys[2]}, weights, hintsKey));
        assertNull(WRAPS.formatRotationMessage(new byte[][] {new byte[0], keys[1], keys[2]}, weights, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, null, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, new long[0], hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, new long[] {-1, 2, 3}, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, new long[] {1, Long.MAX_VALUE, 3}, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, weights, null));
        assertNull(WRAPS.formatRotationMessage(keys, weights, new byte[0]));
    }

    @Test
    public void testConstructWrapsProof() {
        if (!WRAPSLibraryBridge.isProofSupported()) {
            // Gradle script will download artifacts and set TSS_LIB_WRAPS_ARTIFACTS_PATH to bypass this.
            return;
        }

        final Network genesisNetwork = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2),
                Node.from(Constants.SEED_3, 666, 3)));
        final byte[] genesisAddressBookHash =
                WRAPS.hashAddressBook(genesisNetwork.publicKeys(), genesisNetwork.weights());

        final byte[] dummyHintsKey = new byte[1288];

        final byte[] message0 =
                WRAPS.formatRotationMessage(genesisNetwork.publicKeys(), genesisNetwork.weights(), dummyHintsKey);
        final SigningProtocolOutput output0 = aggregateSignature(genesisNetwork, message0);

        System.err.println("Computing proof0 which may take up to 30 minutes...");
        final Proof proof0 = WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true});

        assertEquals(30331352, proof0.uncompressed().length);
        assertEquals(704, proof0.compressed().length);

        // Note: the compressed proof is non-deterministic, so we can only check the size, and then verify it:
        assertTrue(WRAPS.verifyCompressedProof(proof0.compressed(), genesisAddressBookHash, dummyHintsKey));

        if (true) {
            // The above test takes ~30 minutes to run.
            // The below test performs similar actions, simply advancing to the next AB.
            // But essentially, it executes the same math/crypto logic in native code.
            // Yet it takes another 30 minutes to run, which may be expensive.
            // So we short-circuit here, until/unless we:
            // a) implement optional caching for loading proving and verifying keys
            // b) use parallelism in the math to make use of all the CPU cores
            return;
        }

        final Network nextNetwork = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2),
                Node.from(Constants.SEED_3, 666, 3),
                Node.from(Constants.SEED_4, 1666, 4)));

        final AggregationAndVerificationKeys hintsKeys = HINTS.preprocess(
                CRS,
                new int[] {0, 1, 2, 3},
                listToArray(genesisNetwork.nodes().stream().map(Node::hints).toList()),
                genesisNetwork.weights(),
                SIGNERS_NUM);

        final byte[] message1 = WRAPS.formatRotationMessage(
                nextNetwork.publicKeys(), nextNetwork.weights(), hintsKeys.verificationKey());
        final SigningProtocolOutput output1 = aggregateSignature(genesisNetwork, message1);

        System.err.println("Computing proof1 which may take up to 30 minutes...");
        final Proof proof1 = WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                nextNetwork.publicKeys(),
                nextNetwork.weights(),
                proof0.uncompressed(),
                hintsKeys.verificationKey(),
                output1.signature(),
                new boolean[] {true, true, true, true});

        assertEquals(30331352, proof1.uncompressed().length);
        assertEquals(704, proof1.compressed().length);
        assertTrue(
                WRAPS.verifyCompressedProof(proof1.compressed(), genesisAddressBookHash, hintsKeys.verificationKey()));
    }

    @Test
    public void testConstructWrapsProofConstraints() {
        final Network genesisNetwork = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2),
                Node.from(Constants.SEED_3, 666, 3)));
        final byte[] genesisAddressBookHash =
                WRAPS.hashAddressBook(genesisNetwork.publicKeys(), genesisNetwork.weights());

        final byte[] dummyHintsKey = new byte[1288];

        final byte[] message0 =
                WRAPS.formatRotationMessage(genesisNetwork.publicKeys(), genesisNetwork.weights(), dummyHintsKey);
        final SigningProtocolOutput output0 = aggregateSignature(genesisNetwork, message0);

        assertNull(WRAPS.constructWrapsProof(
                null,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                new byte[0],
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                null,
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                new byte[][] {genesisNetwork.publicKeys()[0]},
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    null,
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    new byte[0],
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                null,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                new long[] {1},
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                new long[] {1, -1, 2, 3},
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                new long[] {1, Long.MAX_VALUE, 2, 3},
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                new byte[][] {genesisNetwork.publicKeys()[0]},
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    null,
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    new byte[0],
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                null,
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                new long[] {1},
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                new long[] {1, -1, 2, 3},
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                new long[] {1, Long.MAX_VALUE, 2, 3},
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                null,
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                new byte[0],
                output0.signature(),
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                null,
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                new byte[0],
                new boolean[] {true, true, true, true}));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                null));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                null,
                dummyHintsKey,
                output0.signature(),
                new boolean[] {true}));
    }

    @Test
    public void testVerifyCompressedProofConstraints() {
        assertFalse(WRAPS.verifyCompressedProof(null, new byte[] {0}, new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[0], new byte[] {0}, new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, null, new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, new byte[0], new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, new byte[] {0}, null));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, new byte[] {0}, new byte[0]));
    }
}
