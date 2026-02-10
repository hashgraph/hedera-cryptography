// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import com.hedera.cryptography.ceremony.s3.S3Client;
import com.hedera.cryptography.ceremony.s3.S3ClientInitializationException;
import com.hedera.cryptography.ceremony.s3.S3ResponseException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/// TSS Ceremony Orchestrator.
public class Orchestrator {
    /// Maximum number of cycles of the ceremony.
    private static final int MAX_CYCLES = 100;

    /// Make the loop less tight to reduce the number of S3 API calls in case we keep re-running the last cycle.
    /// Long enough to avoid bombarding S3 with unnecessary requests.
    /// Short enough to allow a human to start a new cycle by uploading the initial.bin/ready whenever needed.
    private static final long WAIT_BETWEEN_CYCLES_MILLIS = 15 * 60 * 1000;

    /// Make the loop less tight to avoid 429 TOO_MANY_REQUESTS.
    private static final long WAIT_IN_DETERMINE_CYCLE_LOOP_MILLIS = 1000;

    /**
     * Main class that requires command-line arguments:
     * <p>
     * $ java Orchestrator thisNodeId nodeId1,nodeId2,... dataCruncherExecutableFile s3Region s3Endpoint s3BucketName keyStorePath keyStorePassword
     * <p>
     * where:
     * - thisNodeId is a long integer that is this nodeId
     * - "nodeId1 nodeId2 ..." is a comma-separated ordered list of long integers of all nodeIds
     * - dataCruncherExecutableFile is a path to the data cruncher (the Rust CLI executable)
     * - s3* specify the S3 location, e.g. `us-east-1 "https://s3.amazonaws.com/" TSSCeremonyBucket"
     * - keyStore* specify the location of the local node key store that contains the node's private key
     *
     * NOTE: TSS_CEREMONY_S3_ACCESS_KEY and TSS_CEREMONY_S3_SECRET_KEY env vars must be defined.
     *
     * The Orchestrator runs continuously and supports multiple cycles (always keeping re-running the last "ready"
     * cycle.) Phases check the ".claimed" files to avoid recomputing and overwriting old data in the current cycle.
     * So continuous re-runs are effectively no-ops after the initial run. To start a new cycle, simply
     * create a new "cycle1", or 2, 3, etc. directory in S3.
     * The initial directory structure in S3 looks like this:
     * - cycle0/parameters/* - static parameters shared by all phases/nodes in a given cycle
     * - cycle0/phase1/initial.bin/* - initial binary files for node0 to pick up as input
     * - cycle0/phase1/initial.ready - a marker to start the cycle0
     *
     * @param args the CLI args
     */
    public static void main(String[] args) throws S3ClientInitializationException {
        if (args.length != 8) {
            System.err.println(
                    "Usage: Orchestrator thisNodeId nodeId1,nodeId2,... dataCruncherExecutableFile s3Region s3Endpoint s3BucketName keyStorePath keyStorePassword");
            return;
        }

        final long thisNodeId = Long.parseLong(args[0]);
        final List<Long> allNodeIds =
                Arrays.stream(args[1].split(",")).map(Long::parseLong).toList();
        final String dataCruncherExecutableFile = args[2];
        final String s3Region = args[3];
        final String s3Endpoint = args[4];
        final String s3BucketName = args[5];
        final String keyStorePath = args[6];
        final String keyStorePassword = args[7];

        final Crypto crypto = new Crypto(thisNodeId, keyStorePath, keyStorePassword.toCharArray());

        final String s3AccessKey = System.getenv("TSS_CEREMONY_S3_ACCESS_KEY");
        final String s3SecretKey = System.getenv("TSS_CEREMONY_S3_SECRET_KEY");

        try (final S3Client s3Client = new S3Client(s3Region, s3Endpoint, s3BucketName, s3AccessKey, s3SecretKey)) {
            System.err.println("Starting Orchestrator for nodeId: " + thisNodeId + " and allNodeIds: " + allNodeIds
                    + " using dataCruncher: " + dataCruncherExecutableFile);

            while (true) {
                try {
                    System.err.println(
                            "Trying to determine a cycle to run (will keep trying until there's one ready)...");
                    final String cycle = determineCycle(s3Client);
                    if (cycle != null) {
                        System.err.println("Running cycle: " + cycle);
                        final Path parametersDir = obtainParameters(s3Client, cycle);
                        final DataCruncher dataCruncher = new DataCruncher(dataCruncherExecutableFile, parametersDir);

                        // Run phase 1
                        new Phase(
                                        "1",
                                        thisNodeId,
                                        allNodeIds,
                                        new S3DirectoryAccessor(s3Client, cycle + "/phase1"),
                                        dataCruncher,
                                        crypto)
                                .run();

                        // Run phase 2
                        new Phase(
                                        "2",
                                        thisNodeId,
                                        allNodeIds,
                                        new S3DirectoryAccessor(s3Client, cycle + "/phase2"),
                                        dataCruncher,
                                        crypto)
                                .run();
                    }
                } catch (S3ResponseException | IOException e) {
                    e.printStackTrace();

                    // An S3 call failed (or maybe a disk read/write failed.) On one hand we could die here.
                    // On the other hand, this may be an intermittent network failure or throttling of some sort,
                    // so let's keep running. We have a Thread.sleep() below to avoid bombarding S3 with bad requests
                    // if it's our fault, actually.
                    // A NodeOp might want to check logs (our stderr/out redirected to a file) to decide if the
                    // process should be killed (e.g. if S3 credentials are indeed bad or similar.)
                }

                try {
                    Thread.sleep(WAIT_BETWEEN_CYCLES_MILLIS);
                } catch (InterruptedException ignore) {
                    // Swallow it to prevent spurious InterruptedExceptions.
                    // We don't really support a graceful shutdown, so an operator would have to kill the process.
                }
            }
        }
    }

    private static String cycleName(int i) {
        return "cycle" + i;
    }

    /// Determine a cycle to run, or null if there's none ready.
    private static String determineCycle(S3Client s3Client) throws S3ResponseException, IOException {
        // It would be nice to list all objects and filter out the pattern we like, but S3 API has a hard-limit
        // of 1000 max_keys for listObject call, and with multiple cycles and phases we could hit the limit.
        // So we loop instead:
        int lastCycle = -1;
        for (int i = 0; i < MAX_CYCLES; i++) {
            final String name = cycleName(i) + "/phase1/" + Phase.INITIAL_FILE_NAME + ".ready";
            final List<String> objects = s3Client.listObjects(name, 2);
            if (objects.size() == 1 && objects.get(0).equals(name)) {
                lastCycle = i;
            }
            try {
                Thread.sleep(WAIT_IN_DETERMINE_CYCLE_LOOP_MILLIS);
            } catch (InterruptedException ignore) {
                // Swallow it to prevent spurious InterruptedExceptions.
                // We don't really support a graceful shutdown, so an operator would have to kill the process.
            }
        }

        return lastCycle == -1 ? null : cycleName(lastCycle);
    }

    // Parameters occupy some 4GB of space. We don't want to keep re-downloading them as we keep re-running
    // the same cycle again and again because it's wasteful. So we cache them.
    private static final Map<String, Path> PARAMETERS_PATHS = new HashMap<>();

    /// Download (if not cached yet) static parameters and return their path
    private static Path obtainParameters(S3Client s3Client, String cycle) throws IOException {
        // Map.computeIfAbsent() is nice, but propagating checked exceptions from lambdas isn't.
        if (PARAMETERS_PATHS.containsKey(cycle)) {
            return PARAMETERS_PATHS.get(cycle);
        }

        System.err.println("Downloading static parameters...");
        final S3DirectoryAccessor s3DirectoryAccessor = new S3DirectoryAccessor(s3Client, cycle);
        final Path parametersDir = s3DirectoryAccessor.downloadDir("parameters");
        PARAMETERS_PATHS.put(cycle, parametersDir);

        return parametersDir;
    }
}
