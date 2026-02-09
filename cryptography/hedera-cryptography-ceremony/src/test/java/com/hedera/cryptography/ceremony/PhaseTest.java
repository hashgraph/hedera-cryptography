// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class PhaseTest {
    private static final String PHASE = "666";
    private static final List<Long> ALL_NODE_IDS = List.of(1L, 2L);

    @Mock
    private S3DirectoryAccessor s3DirectoryAccessor;

    @Mock
    private DataCruncher dataCruncher;

    @Mock
    private Crypto crypto;

    @Test
    void testHappyRunNode1() throws Exception {
        final Path inputPath = Files.createTempDirectory("input");

        final Phase phase = new Phase(PHASE, 1L, ALL_NODE_IDS, s3DirectoryAccessor, dataCruncher, crypto);

        doReturn(true).when(s3DirectoryAccessor).waitForFile(eq("initial.ready"), any(Long.class));
        doReturn(inputPath).when(s3DirectoryAccessor).downloadDir("initial.bin");
        doReturn(0).when(dataCruncher).execute(eq(PHASE), eq(inputPath), any(Path.class));

        phase.run();

        verify(s3DirectoryAccessor, times(1)).writeText("1.claimed", "initial");

        ArgumentCaptor<Path> outputPathCaptor = ArgumentCaptor.forClass(Path.class);
        verify(dataCruncher, times(1)).execute(eq(PHASE), eq(inputPath), outputPathCaptor.capture());
        assertNotNull(outputPathCaptor.getValue());

        verify(crypto, times(1)).signDir(outputPathCaptor.getValue());

        verify(s3DirectoryAccessor, times(1)).uploadDir(outputPathCaptor.getValue(), "1.bin");

        verify(s3DirectoryAccessor, times(1)).writeText("1.ready", "");

        verifyNoMoreInteractions(s3DirectoryAccessor, dataCruncher, crypto);
    }

    @Test
    void testHappyRunNode2() throws Exception {
        final Path inputPath = Files.createTempDirectory("input");

        final Phase phase = new Phase(PHASE, 2L, ALL_NODE_IDS, s3DirectoryAccessor, dataCruncher, crypto);

        doReturn(true).when(s3DirectoryAccessor).waitForFile(eq("initial.ready"), any(Long.class));
        doReturn(true).when(s3DirectoryAccessor).waitForFile(eq("1.ready"), any(Long.class));
        doReturn(inputPath).when(s3DirectoryAccessor).downloadDir("1.bin");
        doReturn(0).when(dataCruncher).execute(eq(PHASE), eq(inputPath), any(Path.class));

        phase.run();

        verify(s3DirectoryAccessor, times(1)).writeText("2.claimed", "1");

        ArgumentCaptor<Path> outputPathCaptor = ArgumentCaptor.forClass(Path.class);
        verify(dataCruncher, times(1)).execute(eq(PHASE), eq(inputPath), outputPathCaptor.capture());
        assertNotNull(outputPathCaptor.getValue());

        verify(crypto, times(1)).signDir(outputPathCaptor.getValue());

        verify(s3DirectoryAccessor, times(1)).uploadDir(outputPathCaptor.getValue(), "2.bin");

        verify(s3DirectoryAccessor, times(1)).writeText("2.ready", "");

        verifyNoMoreInteractions(s3DirectoryAccessor, dataCruncher, crypto);
    }

    @Test
    void testHappyRunNode2Skip1() throws Exception {
        final Path inputPath = Files.createTempDirectory("input");

        final Phase phase = new Phase(PHASE, 2L, ALL_NODE_IDS, s3DirectoryAccessor, dataCruncher, crypto);

        doReturn(true).when(s3DirectoryAccessor).waitForFile(eq("initial.ready"), any(Long.class));
        doReturn(false).when(s3DirectoryAccessor).waitForFile(eq("1.ready"), any(Long.class));
        doReturn(inputPath).when(s3DirectoryAccessor).downloadDir("initial.bin");
        doReturn(0).when(dataCruncher).execute(eq(PHASE), eq(inputPath), any(Path.class));

        phase.run();

        verify(s3DirectoryAccessor, times(1)).writeText("2.claimed", "initial");

        ArgumentCaptor<Path> outputPathCaptor = ArgumentCaptor.forClass(Path.class);
        verify(dataCruncher, times(1)).execute(eq(PHASE), eq(inputPath), outputPathCaptor.capture());
        assertNotNull(outputPathCaptor.getValue());

        verify(crypto, times(1)).signDir(outputPathCaptor.getValue());

        verify(s3DirectoryAccessor, times(1)).uploadDir(outputPathCaptor.getValue(), "2.bin");

        verify(s3DirectoryAccessor, times(1)).writeText("2.ready", "");

        verifyNoMoreInteractions(s3DirectoryAccessor, dataCruncher, crypto);
    }
}
