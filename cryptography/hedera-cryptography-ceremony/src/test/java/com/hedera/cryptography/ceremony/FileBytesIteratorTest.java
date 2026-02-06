// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class FileBytesIteratorTest {
    private static final int THE_5M = 5 * 1024 * 1024;

    record TestCase(int fileSize, int numOfChunks, int lastChunkSize) {}

    static Stream<Arguments> provideTestCases() {
        return Stream.of(
                Arguments.of(new TestCase(0, 1, 0)),
                Arguments.of(new TestCase(1024, 1, 1024)),
                Arguments.of(new TestCase(THE_5M, 2, 0)),
                Arguments.of(new TestCase(THE_5M + 1, 2, 1)),
                Arguments.of(new TestCase(12 * 1024 * 1024, 3, 2 * 1024 * 1024)));
    }

    @ParameterizedTest
    @MethodSource("provideTestCases")
    void testCase(TestCase testCase) throws IOException {
        final Path path = Files.createTempFile("test", "FileBytesIteratorTest");
        final byte[] bytes = new byte[testCase.fileSize];
        Arrays.fill(bytes, (byte) 'a');
        Files.write(path, bytes);

        try (FileBytesIterator fileBytesIterator = new FileBytesIterator(path)) {
            List<byte[]> list = new ArrayList<>();
            while (fileBytesIterator.hasNext()) {
                list.add(fileBytesIterator.next());
            }

            assertEquals(testCase.numOfChunks, list.size());
            if (!list.isEmpty()) {
                assertEquals(testCase.lastChunkSize, list.get(list.size() - 1).length);
            }

            for (int i = 0; i < testCase.numOfChunks; i++) {
                if (i < testCase.numOfChunks - 1) {
                    assertArrayEquals(Arrays.copyOfRange(bytes, i * THE_5M, (i + 1) * THE_5M), list.get(i));
                } else {
                    assertArrayEquals(Arrays.copyOfRange(bytes, i * THE_5M, bytes.length), list.get(i));
                }
            }
        }
    }
}
