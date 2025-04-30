// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.rpm;

import com.hedera.common.nativesupport.NativeBinary;
import com.hedera.common.nativesupport.OperatingSystem;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.Map;

/**
 * A WRAPS proof compressor.
 * <p>
 * Proofs produced by `HistoryLibraryBridge.proveChainOfTrust()` may be large - 1.5 MB or more. In order to be able
 * to include them into frequently produced pieces of data, such as blocks in the Hiero block stream, they need to be
 * compressed to a reasonable size - around 1 KB or so.
 * <p>
 * The current implementation starts a native process using a compiled binary executable from the JAR file,
 * and interacts with the process via stdin/stdout by sending a request, and then reading a reply.
 * Both the request and the reply are essentially a byte array. It's represented on a binary stdin/stdout
 * as a BIG_ENDIAN-encoded 4 bytes length integer prefix followed by the bytes themselves.
 */
public class ProofCompressor {
    private static final NativeBinary COMPRESSOR_EXECUTABLE = new NativeBinary(
            // FUTURE WORK: finalize the actual name of the executable once the Rust/Go build produces it
            // and Gradle packs it into the JAR, same way as it does with our hints and raps libraries.
            // Also, once the actual binary is available, create unit tests for this class.
            "wrapscompressor", Map.of(), Map.of(OperatingSystem.WINDOWS, "exe"));

    /**
     * Compress the given WRAPS proof.
     *
     * @param input a WRAPS proof as obtained from `HistoryLibraryBridge.proveChainOfTrust()`
     * @return a compressed version of the proof, or null if any errors occur
     */
    public static byte[] compressProof(final byte[] input) {
        Process process = null;
        try {
            // Start the process
            final Path path = COMPRESSOR_EXECUTABLE.extract(ProofCompressor.class);
            final ProcessBuilder pb =
                    new ProcessBuilder().command(path.toAbsolutePath().toString());
            process = pb.start();

            // Send the input by writing a BIG_ENDIAN 4 bytes integer length followed by the input bytes
            final OutputStream os = process.getOutputStream();
            os.write(intToArray(input.length));
            os.flush();
            os.write(input);
            os.flush();

            // Receive the output by reading a BIG_ENDIAN 4 bytes integer length followed by the output bytes
            final InputStream is = process.getInputStream();
            final byte[] lenBytes = is.readNBytes(4);
            final int len = arrayToInt(lenBytes);
            final byte[] output = is.readNBytes(len);
            if (output.length != len) {
                return null;
            }

            return output;
        } catch (Exception e) {
            // This is mostly for the IOException, but the NativeBinary, ProcessBuilder, and our arrayToInt() may throw
            // various exceptions, too, so we catch all of them here.
            return null;
        } finally {
            if (process != null) {
                // The process is supposed to exit on its own once it emits the reply, so this will likely be a no-op.
                // But it's here in case we catch an exception before the process had a chance to receive any input.
                // This should help prevent a memory leak in case we keep spawning new processes and erroring out
                // continuously due to a bug or similar.
                process.destroy();
            }
        }
    }

    /** Return BIG_ENDIAN-encoded integer bytes. */
    private static byte[] intToArray(final int value) {
        return new byte[] {(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }

    /** Unencode a BIG_ENDIAN integer from a byte array. */
    private static int arrayToInt(final byte[] array) {
        return ((array[0] & 0xFF) << 24)
                | ((array[1] & 0xFF) << 16)
                | ((array[2] & 0xFF) << 8)
                | ((array[3] & 0xFF) << 0);
    }
}
