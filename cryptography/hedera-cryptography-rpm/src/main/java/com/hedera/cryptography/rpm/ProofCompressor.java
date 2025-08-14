// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import com.hedera.common.nativesupport.NativeBinary;
import com.hedera.common.nativesupport.OperatingSystem;
import com.hedera.common.nativesupport.SingletonLoader;
import com.hedera.common.nativesupport.api.ProcessAPI;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

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

    private static final String EXECUTABLE_NAME = "compressor";

    private static final NativeBinary compressorBinary =
            new NativeBinary(EXECUTABLE_NAME, Map.of(), Map.of(OperatingSystem.WINDOWS, "exe"));

    private static final String TSS_MARKER = "<TSS OUTPUT BEGIN>";

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        ProofCompressor.class
                .getModule()
                .addOpens(compressorBinary.packageNameOfResource(), SingletonLoader.class.getModule());
    }

    /**
     * Check if the compression is supported.
     * <p>
     * An environment variable should be set to point to a directory containing a "v5.0.0" sub-directory
     * with files such as: groth16_circuit.bin , groth16_witness.json , and others.
     *
     * @return true if the compression is supported
     */
    public static boolean isSupported() {
        return System.getenv("SP1_GROTH16_CIRCUIT_PATH") != null;
    }

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
        if (!isSupported()) {
            return null;
        }

        AtomicReference<InputStream> errStream = new AtomicReference<>();
        try (final ProcessAPI processAPI = new ProcessAPI(ProofCompressor.class, compressorBinary)) {
            errStream.set(processAPI.getErrorStream());

            processAPI.sendArray(proverKey);
            processAPI.sendArray(verificationKey);
            processAPI.sendArray(uncompressedProof);

            final InputStream inStream = processAPI.getInputStream();
            int markerMatch = 0;
            int c;
            while ((c = inStream.read()) != -1) {
                // sp1 emits debugging output to stdout, so we print it to our stderr
                // until we encounter our marker:
                System.err.print((char) c);
                if (c == TSS_MARKER.charAt(markerMatch)) {
                    markerMatch++;
                    if (markerMatch == TSS_MARKER.length()) {
                        break;
                    }
                } else {
                    markerMatch = 0;
                }
            }

            if (c == -1) {
                // Looks like we never got our marker, and the stream is closed already,
                // so just error out here:
                errStream.get().transferTo(System.err);
                return null;
            }

            return processAPI.receiveArray();
        } catch (Exception e) {
            // Previously we agreed to return `null` in case of any errors, so:
            System.err.println("Error compressing proof: " + e.getMessage());
            e.printStackTrace();
            if (errStream.get() != null) {
                try {
                    System.err.println("stderr start: -------------------------------- ");
                    errStream.get().transferTo(System.err);
                    System.err.println("stderr finish: ------------------------------- ");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
            return null;
        }
    }
}
