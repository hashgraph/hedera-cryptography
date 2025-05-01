// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.Map;

/**
 * An AutoCloseable native process runner that allows one to interact with it via stdin/stdout by means
 * of sending and receiving byte arrays using public methods in this class.
 */
public class ProcessAPI implements AutoCloseable {
    private final Process process;

    /**
     * Create a new ProcessAPI instance and start the process.
     * The process should normally exit once it'd done its job - e.g. completed an API call.
     * However, applications may also call `ProcessAPI.close()` or use a try-with-resources to
     * `Process.destroy()` the underlying process.
     *
     * @param clz a class that is in the Java module where the executable belongs to
     * @param executableName a name of the executable file as present in the JAR file
     * @throws IOException if any errors occur when extracting the executable or starting the process
     */
    public ProcessAPI(final Class<?> clz, final String executableName) throws IOException {
        final NativeBinary executableBinary =
                new NativeBinary(executableName, Map.of(), Map.of(OperatingSystem.WINDOWS, "exe"));
        final Path path = executableBinary.extract(clz);
        final ProcessBuilder pb =
                new ProcessBuilder().command(path.toAbsolutePath().toString());
        this.process = pb.start();
    }

    @Override
    public void close() throws Exception {
        // The process is supposed to exit on its own once it emits the reply, so this will likely be a no-op.
        // But it's here in case we catch an exception before the process had a chance to receive any input.
        // This should help prevent a memory leak in case we keep spawning new processes and erroring out
        // continuously due to a bug or similar.
        this.process.destroy();
    }

    /**
     * Send a byte array by writing a BIG_ENDIAN 4 bytes integer length followed by the array bytes.
     * @param array a byte array to send
     */
    public void sendArray(final byte[] array) throws IOException {
        final OutputStream os = process.getOutputStream();

        os.write(intToArray(array.length));
        os.flush();
        os.write(array);
        os.flush();
    }

    /**
     * Receive a byte array by reading a BIG_ENDIAN 4 bytes integer length followed by the array bytes.
     * @return the received array, or null if the InputStream is closed before receiving all the bytes
     */
    public byte[] receiveArray() throws IOException {
        final InputStream is = process.getInputStream();

        final byte[] lenBytes = is.readNBytes(4);
        final int len = arrayToInt(lenBytes);
        final byte[] output = is.readNBytes(len);
        if (output.length != len) {
            return null;
        }

        return output;
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
