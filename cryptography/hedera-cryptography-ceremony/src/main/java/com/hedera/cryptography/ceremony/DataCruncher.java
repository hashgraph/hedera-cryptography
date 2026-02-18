// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import com.hedera.common.nativesupport.NativeBinary;
import com.hedera.common.nativesupport.OperatingSystem;
import com.hedera.common.nativesupport.SingletonLoader;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/// Utility to run a Rust executable
class DataCruncher {
    /// 3 hours seems more than enough
    private static final long PROCESS_WAIT_TIMEOUT_MILLIS = 3 * 60 * 60 * 1000;

    private static final String EXECUTABLE_NAME = "ceremony";
    private static final NativeBinary CEREMONY_BINARY =
            new NativeBinary(EXECUTABLE_NAME, Map.of(), Map.of(OperatingSystem.WINDOWS, "exe"));

    /// Full path to the executable
    private static final Path EXECUTABLE_PATH;

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        DataCruncher.class
                .getModule()
                .addOpens(CEREMONY_BINARY.packageNameOfResource(), SingletonLoader.class.getModule());

        // Extract it just once because we keep creating new DataCruncher objects in the Orchestrator
        EXECUTABLE_PATH = CEREMONY_BINARY.extract(DataCruncher.class);
    }


    /// Full path to static parameters of the current cycle shared between all phases/nodes/runs.
    private final Path parametersPath;

    DataCruncher(Path parametersPath) {
        this.parametersPath = parametersPath;
    }

    /// Run the data cruncher and return its exit code
    int execute(String phase, Path inputPath, Path outputPath) throws IOException {
        final ProcessBuilder pb = new ProcessBuilder()
                .command(
                        EXECUTABLE_PATH.toAbsolutePath().toString(),
                        phase,
                        parametersPath.toAbsolutePath().toString(),
                        inputPath.toAbsolutePath().toString(),
                        outputPath.toAbsolutePath().toString());

        final Process process = pb.start();
        try {
            if (!process.waitFor(PROCESS_WAIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                System.err.println("Timed out waiting for process");
                return Integer.MIN_VALUE;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Integer.MIN_VALUE;
        }

        return process.exitValue();
    }
}
