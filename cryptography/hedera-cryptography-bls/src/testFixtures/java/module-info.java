module com.hedera.cryptography.bls.testFixtures {
    requires com.hedera.cryptography.utils.test.fixtures;
    requires static transitive com.hedera.cryptography.bls;

    exports com.hedera.cryptography.bls.test.fixtures;
}
