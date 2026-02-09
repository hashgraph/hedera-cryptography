// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony;

import com.hedera.cryptography.ceremony.s3.S3Client;
import com.hedera.cryptography.ceremony.s3.S3ClientInitializationException;
import java.util.Arrays;
import java.util.List;

public class Orchestrator {
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

        final DataCruncher dataCruncher = new DataCruncher(dataCruncherExecutableFile);
        try (final S3Client s3Client = new S3Client(s3Region, s3Endpoint, s3BucketName, s3AccessKey, s3SecretKey)) {
            System.err.println("Starting Orchestrator for nodeId: " + thisNodeId + " and allNodeIds: " + allNodeIds
                    + " using dataCruncher: " + dataCruncherExecutableFile);

            // Run phase 1
            new Phase("1", thisNodeId, allNodeIds, new S3DirectoryAccessor(s3Client, "phase1"), dataCruncher, crypto)
                    .run();

            // Run phase 2
            new Phase("2", thisNodeId, allNodeIds, new S3DirectoryAccessor(s3Client, "phase2"), dataCruncher, crypto)
                    .run();
        }
    }
}
