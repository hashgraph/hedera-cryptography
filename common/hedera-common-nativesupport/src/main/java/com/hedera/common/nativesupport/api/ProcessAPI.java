// SPDX-License-Identifier: Apache-2.0
package com.hedera.common.nativesupport.api;

import com.hedera.common.nativesupport.NativeBinary;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;

/**
 * An implementation of the ExternalAPI that extends the abstract StreamAPI, runs a native process,
 * and allows one to interact with it via stdin/stdout by means of sending and receiving byte arrays
 * using public methods from the ExternalAPI.
 */
public class ProcessAPI extends StreamAPI {
    private final Process process;

    /**
     * Create a new ProcessAPI instance and start the process.
     * The process should normally exit once it'd done its job - e.g. completed an API call.
     * However, applications may also call `ProcessAPI.close()` or use a try-with-resources to
     * `Process.destroy()` the underlying process.
     *
     * @param clz a class that is in the Java module where the executable belongs to
     * @param executableBinary a NativeBinary for the executable file as present in the JAR file
     * @throws IOException if any errors occur when extracting the executable or starting the process
     */
    public ProcessAPI(final Class<?> clz, final NativeBinary executableBinary) throws IOException {
        final Path path = executableBinary.extract(clz);
        final ProcessBuilder pb =
                new ProcessBuilder().command(path.toAbsolutePath().toString());
        this.process = pb.start();
    }

    @Override
    public void close() throws Exception {
        // Release all resources
        getOutputStream().close();
        getInputStream().close();
        getErrorStream().close();

        // The process is supposed to exit on its own once it emits the reply, so this will likely be a no-op.
        // But it's here in case we catch an exception before the process had a chance to receive any input.
        // This should help prevent a memory leak in case we keep spawning new processes and erroring out
        // continuously due to a bug or similar.
        this.process.destroy();
    }

    @Override
    protected OutputStream getOutputStream() {
        return process.getOutputStream();
    }

    @Override
    public InputStream getInputStream() {
        return process.getInputStream();
    }

    public InputStream getErrorStream() {
        return process.getErrorStream();
    }
}
