// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport.api;

import java.io.IOException;

/**
 * An interface for an external API that is likely running outside the current JVM process.
 * <p>
 * For example, an implementation could start a separate process to call the API, or call
 * an external service via a network connection.
 * <p>
 * The interface extends `AutoCloseable` because in most cases external APIs would need to clean up
 * some resources - e.g. destroy the external process, or close network connections, etc.
 */
public interface ExternalAPI extends AutoCloseable {
    /**
     * Send an input argument to the external API in the form of a byte array.
     * @param array an array to send
     * @throws IOException if any errors occur
     */
    void sendArray(final byte[] array) throws IOException;

    /**
     * Block and receive an output of the external API in the form of a byte array.
     * @return the output byte array
     * @throws IOException if any errors occur
     */
    byte[] receiveArray() throws IOException;
}
