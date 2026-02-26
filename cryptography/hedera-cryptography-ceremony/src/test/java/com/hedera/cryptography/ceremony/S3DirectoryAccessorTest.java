// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.hedera.cryptography.ceremony.s3.S3Client;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class S3DirectoryAccessorTest {
    private static final String DIR = "dir/";
    private static final String STORAGE_CLASS = "STANDARD";
    private static final String BINARY_CONTENT_TYPE = "application/octet-stream";

    @Mock
    private S3Client s3Client;

    @Test
    void testDoesExist() throws Exception {
        S3DirectoryAccessor instance = new S3DirectoryAccessor(s3Client, DIR);

        doReturn(List.of(DIR + "test")).when(s3Client).listObjects(DIR + "test", 2);
        assertTrue(instance.doesExist("test"));

        doReturn(List.of()).when(s3Client).listObjects(DIR + "test", 2);
        assertFalse(instance.doesExist("test"));

        doReturn(List.of(DIR + "test", "another")).when(s3Client).listObjects(DIR + "test", 2);
        assertFalse(instance.doesExist("test"));
    }

    @Test
    void testWaitForFile() throws Exception {
        S3DirectoryAccessor instance = new S3DirectoryAccessor(s3Client, DIR);

        doReturn(List.of(DIR + "test")).when(s3Client).listObjects(DIR + "test", 2);
        assertTrue(instance.waitForFile("test", 10));

        doReturn(List.of()).doReturn(List.of(DIR + "test")).when(s3Client).listObjects(DIR + "test", 2);
        assertTrue(instance.waitForFile("test", -20));

        doReturn(List.of()).when(s3Client).listObjects(DIR + "test", 2);
        assertFalse(instance.waitForFile("test", -20));
    }

    @Test
    void testWriteText() throws Exception {
        S3DirectoryAccessor instance = new S3DirectoryAccessor(s3Client, DIR);

        instance.writeText("test", "text");

        verify(s3Client, times(1)).uploadTextFile(DIR + "test", STORAGE_CLASS, "text");
        verifyNoMoreInteractions(s3Client);
    }

    @Test
    void testEnsureSlash() throws Exception {
        // NOTE: "dir" is missing the trailing slash:
        S3DirectoryAccessor instance = new S3DirectoryAccessor(s3Client, "dir");
        // The client should've added the slash in the ctor, so the below test must behave exactly as the
        // testWriteText() above

        instance.writeText("test", "text");

        verify(s3Client, times(1)).uploadTextFile(DIR + "test", STORAGE_CLASS, "text");
        verifyNoMoreInteractions(s3Client);
    }

    @Test
    void testDownloadDir() throws Exception {
        S3DirectoryAccessor instance = new S3DirectoryAccessor(s3Client, DIR);

        doReturn(List.of(DIR + "test/1.txt", DIR + "test/1.sig", DIR + "test/2.bin"))
                .when(s3Client)
                .listObjects(DIR + "test/", 1000);

        final Path path = instance.downloadDir("test");
        assertNotNull(path);

        verify(s3Client, times(1)).downloadFile(DIR + "test/1.txt", path.resolve("1.txt"));
        verify(s3Client, times(1)).downloadFile(DIR + "test/1.sig", path.resolve("1.sig"));
        verify(s3Client, times(1)).downloadFile(DIR + "test/2.bin", path.resolve("2.bin"));
        verifyNoMoreInteractions(s3Client);
    }

    @Test
    void testUploadDir() throws Exception {
        final Path path = Files.createTempDirectory("local");
        Files.write(path.resolve("1.txt"), "text".getBytes());
        Files.write(path.resolve("1.sig"), "sig".getBytes());
        Files.write(path.resolve("2.bin"), "bin".getBytes());

        S3DirectoryAccessor instance = new S3DirectoryAccessor(s3Client, DIR);

        instance.uploadDir(path, "remote");

        ArgumentCaptor<Iterator<byte[]>> bytesIteratorCaptor = ArgumentCaptor.forClass(Iterator.class);

        // NOTE: S3DirectoryAccessor has a try (new iterator()) {}, so the iterator is closed and cannot be examined
        // further.
        // So, unfortunately, we cannot check if it uploads the exact content that we wrote to the files above.
        // Unless we introduce a FileBytesIteratorFactory to the S3DirectoryAccessor to control the lifecycle
        // of the iterators, but that's too much extra complexity only for tests, so not worth it.

        verify(s3Client, times(1))
                .uploadFile(
                        eq(DIR + "remote/1.txt"),
                        eq(STORAGE_CLASS),
                        bytesIteratorCaptor.capture(),
                        eq(BINARY_CONTENT_TYPE));
        assertFalse(bytesIteratorCaptor.getValue().hasNext());

        verify(s3Client, times(1))
                .uploadFile(
                        eq(DIR + "remote/1.sig"),
                        eq(STORAGE_CLASS),
                        bytesIteratorCaptor.capture(),
                        eq(BINARY_CONTENT_TYPE));
        assertFalse(bytesIteratorCaptor.getValue().hasNext());

        verify(s3Client, times(1))
                .uploadFile(
                        eq(DIR + "remote/2.bin"),
                        eq(STORAGE_CLASS),
                        bytesIteratorCaptor.capture(),
                        eq(BINARY_CONTENT_TYPE));
        assertFalse(bytesIteratorCaptor.getValue().hasNext());

        verifyNoMoreInteractions(s3Client);
    }
}
