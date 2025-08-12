// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport.api;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An abstract implementation of the ExternalAPI interface that uses an OutputStream and an InputStream
 * to communicate with the API.
 * <p>
 * For example, a descendant could start a local process and expose its stdin/stdout via the streams.
 * Alternatively, a descendant could open a network connection to a remote service and expose the connection's
 * streams for this purpose.
 * <p>
 * An array is represented on the streams as a BIG_ENDIAN 4 bytes integer length followed by the array bytes.
 */
public abstract class StreamAPI implements ExternalAPI {

    /** @return an OutputStream for the API to receive data from the client. */
    protected abstract OutputStream getOutputStream();

    /** @return an InputStream for the API to provide results to the client. */
    protected abstract InputStream getInputStream();

    /**
     * Send a byte array by writing a BIG_ENDIAN 4 bytes integer length followed by the array bytes.
     * @param array a byte array to send
     */
    @Override
    public void sendArray(final byte[] array) throws IOException {
        final OutputStream os = getOutputStream();

        os.write(intToArray(array.length));
        os.flush();
        os.write(array);
        os.flush();
    }

    /**
     * Receive a byte array by reading a BIG_ENDIAN 4 bytes integer length followed by the array bytes.
     * @return the received array, or null if the InputStream is closed before receiving all the bytes
     */
    @Override
    public byte[] receiveArray() throws IOException {
        final InputStream is = getInputStream();

        final byte[] lenBytes = is.readNBytes(4);
        if (lenBytes.length != 4) {
            throw new EOFException("Expected 4 bytes in length array, got " + lenBytes.length);
        }
        final int len = arrayToInt(lenBytes);
        final byte[] output = is.readNBytes(len);
        if (output.length != len) {
            throw new EOFException("Expected " + len + " bytes in data array, got " + output.length);
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
