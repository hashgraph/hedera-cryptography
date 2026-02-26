// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Iterator;

/// Utility to read large files in 5MB chunks to feed the S3 uploader.
class FileBytesIterator implements Iterator<byte[]>, AutoCloseable {
    /// S3 multipart uses chunks of 5MB
    private static final int BUFFER_SIZE = 5 * 1024 * 1024;
    private static final byte[] EMPTY_BYTES = new byte[0];
    private final byte[] buffer = new byte[BUFFER_SIZE];

    private final InputStream in;
    private boolean eof = false;

    FileBytesIterator(Path file) throws IOException {
        in = new FileInputStream(file.toFile());
    }

    @Override
    public boolean hasNext() {
        return !eof;
    }

    @Override
    public byte[] next() {
        try {
            final int read = in.readNBytes(buffer, 0, buffer.length);
            if (read == buffer.length) {
                return buffer;
            } else {
                eof = true;
                if (read == 0) {
                    return EMPTY_BYTES;
                } else {
                    return Arrays.copyOf(buffer, read);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void close() throws IOException {
        eof = true;
        in.close();
    }
}
