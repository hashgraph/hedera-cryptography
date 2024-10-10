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

package com.hedera.cryptography.eckeygen;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Container for the command line arguments.
 */
public final class CliArguments {
    private final CliCommand command;
    private final Path privateKeyPath;
    private final Path publicKeyPath;

    private CliArguments(
            @NonNull final CliCommand command,
            @Nullable final Path privateKeyPath,
            @Nullable final Path publicKeyPath) {
        this.command = command;
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
    }

    /**
     * Parse the command line arguments
     * @param args the command line arguments passed to main()
     * @return the parsed arguments
     */
    @NonNull
    public static CliArguments parse(@NonNull final String[] args) {
        if (args.length == 0 || args[0].equals("--help") || args.length != 3) {
            new CliArguments(CliCommand.PRINT_HELP, null, null);
        }
        return switch (args[0]) {
            case "generate-keys" -> new CliArguments(CliCommand.GENERATE_KEYS, Path.of(args[1]), Path.of(args[2]));
            case "generate-public-key" -> new CliArguments(
                    CliCommand.GENERATE_PUBLIC_KEY, Path.of(args[1]), Path.of(args[2]));
            default -> new CliArguments(CliCommand.PRINT_HELP, null, null);
        };
    }

    /**
     * @return the command to execute
     */
    @NonNull
    public CliCommand command() {
        return command;
    }

    /**
     * @return the path to the private key file
     * @throws NullPointerException if the command does not require a private key file
     */
    @NonNull
    public Path privateKeyPath() {
        return Objects.requireNonNull(privateKeyPath);
    }

    /**
     * @return the path to the public key file
     * @throws NullPointerException if the command does not require a public key file
     */
    @NonNull
    public Path publicKeyPath() {
        return Objects.requireNonNull(publicKeyPath);
    }
}
