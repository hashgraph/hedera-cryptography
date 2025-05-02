// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import com.hedera.common.nativesupport.ProcessAPI;

/**
 * A WRAPS proof compressor.
 * <p>
 * Proofs produced by `HistoryLibraryBridge.proveChainOfTrust()` may be large - 1.5 MB or more. In order to be able
 * to include them into frequently produced pieces of data, such as blocks in the Hiero block stream, they need to be
 * compressed to a reasonable size - around 1 KB or so.
 * <p>
 * The current implementation uses the ProcessAPI class to run the compression as a separate process. See JavaDoc
 * for that class for details on the binary representation of the byte arrays in stdin/stdout.
 */
public class ProofCompressor {
    /**
     * Compress the given WRAPS proof.
     *
     * @param proverKey the prover key for the compression zkVM
     * @param verificationKey the verification key for the uncompressed zkVM
     * @param uncompressedProof a WRAPS proof as obtained from `HistoryLibraryBridge.proveChainOfTrust()`
     * @return a compressed version of the proof, or null if any errors occur
     */
    public static byte[] compressProof(
            final byte[] proverKey, final byte[] verificationKey, final byte[] uncompressedProof) {
        // FUTURE WORK: finalize the actual name of the executable once the Rust/Go build produces it
        // and Gradle packs it into the JAR, same way as it does with our hints and raps libraries.
        // Also, once the actual binary is available, create unit tests for this class.
        try (final ProcessAPI processAPI = new ProcessAPI(ProofCompressor.class, "wrapscompressor")) {
            processAPI.sendArray(proverKey);
            processAPI.sendArray(verificationKey);
            processAPI.sendArray(uncompressedProof);

            return processAPI.receiveArray();
        } catch (Exception e) {
            // Previously we agreed to return `null` in case of any errors, so:
            return null;
        }
    }
}
