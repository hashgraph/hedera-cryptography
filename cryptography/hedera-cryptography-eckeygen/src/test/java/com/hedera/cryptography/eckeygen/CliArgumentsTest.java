package com.hedera.cryptography.eckeygen;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class CliArgumentsTest {

    @Test
    void noArgs() {
        final CliArguments args = CliArguments.parse(new String[0]);
        assertEquals(CliCommand.PRINT_HELP, args.command());
        assertThrows(NullPointerException.class, args::privateKeyPath);
        assertThrows(NullPointerException.class, args::publicKeyPath);
    }

    @Test
    void unknownCommand() {
        final CliArguments args = CliArguments.parse(new String[]{"some", "random", "args"});
        assertEquals(CliCommand.PRINT_HELP, args.command());
    }

    @Test
    void insufficientArgs() {
        final CliArguments args = CliArguments.parse(new String[]{"generate-keys", "private"});
        assertEquals(CliCommand.PRINT_HELP, args.command());
        assertThrows(NullPointerException.class, args::privateKeyPath);
        assertThrows(NullPointerException.class, args::publicKeyPath);
    }

    @Test
    void generateKeysCommand() {
        final CliArguments args = CliArguments.parse(new String[]{"generate-keys", "private", "public"});
        assertEquals(CliCommand.GENERATE_KEYS, args.command());
        assertNotNull(args.privateKeyPath());
        assertNotNull(args.publicKeyPath());
    }
}