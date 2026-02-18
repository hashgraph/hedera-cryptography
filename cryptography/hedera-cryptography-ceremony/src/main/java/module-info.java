// SPDX-License-Identifier: Apache-2.0
/**
 */
module com.hedera.cryptography.ceremony {
    exports com.hedera.cryptography.ceremony;

    requires com.hedera.common.nativesupport;
    requires java.logging;
    requires java.net.http;
    requires java.xml;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
}
