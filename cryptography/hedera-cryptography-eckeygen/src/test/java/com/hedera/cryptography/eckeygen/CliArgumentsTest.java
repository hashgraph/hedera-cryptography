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
        final CliArguments args = CliArguments.parse(new String[] {"some", "random", "args"});
        assertEquals(CliCommand.PRINT_HELP, args.command());
    }

    @Test
    void insufficientArgs() {
        final CliArguments args = CliArguments.parse(new String[] {"generate-keys", "private"});
        assertEquals(CliCommand.PRINT_HELP, args.command());
        assertThrows(NullPointerException.class, args::privateKeyPath);
        assertThrows(NullPointerException.class, args::publicKeyPath);
    }

    @Test
    void generateKeysCommand() {
        final CliArguments args = CliArguments.parse(new String[] {"generate-keys", "private", "public"});
        assertEquals(CliCommand.GENERATE_KEYS, args.command());
        assertNotNull(args.privateKeyPath());
        assertNotNull(args.publicKeyPath());
    }
}
