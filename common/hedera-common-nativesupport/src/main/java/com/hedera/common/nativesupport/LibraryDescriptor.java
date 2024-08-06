/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hedera.common.nativesupport;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.File;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 *
 * @implNote This method expects the executable to be present at the following location in the JAR file:
 * {@code /software/<os>/<arch>/libraryName}.
 *
 * @param libraryName the library to load.
 * @param libExtensions defaults extensions for each os to use to load the library
 * @see Architecture
 * @see OperatingSystem
 */
public record LibraryDescriptor(@NonNull String libraryName, @NonNull Map<OperatingSystem, String> libExtensions) {
    /**
     * The root resources folder where the software is located.
     */
    private static final String SOFTWARE_FOLDER_NAME = "software";

    /**
     * The path delimiter used in the JAR file.
     */
    private static final String RESOURCE_PATH_DELIMITER = File.separator;

    /**
     * Default extensions for binary libraries per OS
     */
    static Map<OperatingSystem, String> DEFAULT_LIB_EXTENSIONS =
            Map.of(OperatingSystem.WINDOWS, "dll", OperatingSystem.LINUX, "so", OperatingSystem.DARWIN, "dylib");

    /**
     * @implNote This method expects the executable to be present at the following location in the JAR file:
     * {@code /software/<os>/<arch>/libraryName}.
     */
    public String getLocation() {
        return getLocation(this.libraryName, this.libExtensions);
    }

    public static LibraryDescriptor create(
            @NonNull String libraryName, @NonNull Map<OperatingSystem, String> libExtensions) {
        return new LibraryDescriptor(libraryName, libExtensions);
    }

    public static LibraryDescriptor create(@NonNull String libraryName) {
        return create(libraryName, DEFAULT_LIB_EXTENSIONS);
    }

    /**
     *
     * @implNote This method expects the executable to be present at the following location in the JAR file:
     * {@code /software/<os>/<arch>/libraryName}.
     */
    public static String getLocation(@NonNull String libraryName, @NonNull Map<OperatingSystem, String> libExtensions) {
        Objects.requireNonNull(libraryName, "libraryName must not be null");
        Objects.requireNonNull(libExtensions, "libExtensions must not be null");
        final OperatingSystem os = OperatingSystem.current();
        final Architecture arch = Architecture.current();

        String libExtension = libExtensions.get(os);
        if (!libExtensions.isEmpty()) {
            libExtension = "." + libExtension;
        }
        return SOFTWARE_FOLDER_NAME
                + RESOURCE_PATH_DELIMITER
                + os.name().toLowerCase(Locale.US)
                + RESOURCE_PATH_DELIMITER
                + arch.name().toLowerCase(Locale.US)
                + RESOURCE_PATH_DELIMITER
                + libraryName
                + libExtension;
    }
}
