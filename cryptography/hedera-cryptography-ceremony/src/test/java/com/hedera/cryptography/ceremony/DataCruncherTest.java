// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

/// We just test if we can launch an external process and get an expected exit code value.
/// Cannot do that on Windows because there may not be /usr/bin/*.
@DisabledOnOs(OS.WINDOWS)
public class DataCruncherTest {
    @Test
    void testTrue() throws IOException {
        final DataCruncher dataCruncher = new DataCruncher("/usr/bin/true");
        final int status = dataCruncher.execute("", Path.of("."), Path.of("."));
        assertEquals(0, status);
    }

    @Test
    void testFalse() throws IOException {
        final DataCruncher dataCruncher = new DataCruncher("/usr/bin/false");
        final int status = dataCruncher.execute("", Path.of("."), Path.of("."));
        assertNotEquals(0, status);
    }
}
