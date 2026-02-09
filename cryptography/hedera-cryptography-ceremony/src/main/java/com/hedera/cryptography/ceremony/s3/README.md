This is a copy of https://github.com/hiero-ledger/hiero-block-node/tree/main/block-node/base/src/main/java/org/hiero/block/node/base/s3
Minor changes:
- removed dependencies on a couple of utility classes/methods in the Block Node repo (Preconditions and StringUtils)
- remove a dependency on edu.umd.cs.findbugs.annotations which doesn't work in this repo
- added long S3Client.downloadFile(final String key, final Path path)
