// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class ProofCompressorTest {
    private static final HistoryLibraryBridge HISTORY = HistoryLibraryBridge.getInstance();

    @Test
    public void compressorTest() throws Exception {
        if (!ProofCompressor.isSupported()) {
            // This test is only relevant if compression is supported.
            return;
        }

        final ProvingAndVerifyingSnarkKeys snarkKeysFromABRotationProgram =
                HISTORY.snarkVerificationKey(HistoryLibraryBridge.loadAddressBookRotationProgram());

        final ProvingAndVerifyingSnarkKeys snarkKeysFromRapsCompressionProgram =
                HISTORY.snarkVerificationKey(HistoryLibraryBridge.loadRapsCompressionProgram());

        final byte[] proof = HistoryLibraryBridgeTest.computeProof(snarkKeysFromABRotationProgram);

        final byte[] compressedProof = ProofCompressor.compressProof(
                snarkKeysFromRapsCompressionProgram.provingKey(), snarkKeysFromABRotationProgram.verifyingKey(), proof);

        // NOTE: the compressed proof is non-deterministic by design, so we cannot assert equality with a constant.
        // But we can and should verify it, so:
        assertTrue(HISTORY.verifyCompressedChainOfTrust(
                snarkKeysFromRapsCompressionProgram.verifyingKey(), compressedProof));
    }
}
