package com.hedera.cryptography.eckeygen;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.nio.file.Path;
import java.util.Objects;

public final class CliArguments {
    private final CliCommand command;
    private final Path privateKeyPath;
    private final Path publicKeyPath;

    private CliArguments(@NonNull final CliCommand command, @Nullable final Path privateKeyPath, @Nullable final Path publicKeyPath) {
        this.command = command;
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
    }

    public static CliArguments parse(@NonNull final String[] args) {
        if (args.length == 0 || args[0].equals("--help") || args.length != 3) {
            new CliArguments(CliCommand.PRINT_HELP, null, null);
        }
        return switch (args[0]){
            case "generate-keys" -> new CliArguments(CliCommand.GENERATE_KEYS, Path.of(args[1]), Path.of(args[2]));
            case "generate-public-key"-> new CliArguments(CliCommand.GENERATE_PUBLIC_KEY, Path.of(args[1]), Path.of(args[2]));
            default-> new CliArguments(CliCommand.PRINT_HELP, null, null);
        };
    }

    @NonNull
    public CliCommand command() {return command;}
    @NonNull
    public Path privateKeyPath() {return Objects.requireNonNull(privateKeyPath);}
    @NonNull
    public Path publicKeyPath() {return Objects.requireNonNull(publicKeyPath);}
}
