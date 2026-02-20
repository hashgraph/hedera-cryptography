// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import com.hedera.common.nativesupport.NativeBinary;
import com.hedera.common.nativesupport.OperatingSystem;
import com.hedera.common.nativesupport.SingletonLoader;
import java.nio.file.Path;
import java.util.Map;

/// A handle for the Rust executable
public class CeremonyExecutable {
    private static final String EXECUTABLE_NAME = "ceremony";
    private static final NativeBinary CEREMONY_BINARY =
            new NativeBinary(EXECUTABLE_NAME, Map.of(), Map.of(OperatingSystem.WINDOWS, "exe"));

    /// Full path to the executable
    static final Path EXECUTABLE_PATH;

    static {
        // Open the package to allow access to the native library
        // This can be done in module-info.java as well, but by default the compiler complains since there are no
        // classes in the package, just resources
        CeremonyExecutable.class
                .getModule()
                .addOpens(CEREMONY_BINARY.packageNameOfResource(), SingletonLoader.class.getModule());

        // Extract it just once because we keep creating new DataCruncher objects in the Orchestrator
        EXECUTABLE_PATH = CEREMONY_BINARY.extract(CeremonyExecutable.class);
    }
}
