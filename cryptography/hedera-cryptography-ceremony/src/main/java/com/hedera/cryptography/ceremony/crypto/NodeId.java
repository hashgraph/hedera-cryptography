// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.ceremony.crypto;

public record NodeId(long id) {
    public String formatNodeName() {
        return "node" + (id + 1);
    }
}
