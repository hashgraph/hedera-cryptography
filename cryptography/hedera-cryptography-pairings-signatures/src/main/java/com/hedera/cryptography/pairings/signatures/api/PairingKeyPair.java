package com.hedera.cryptography.pairings.signatures.api;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

public record PairingKeyPair(@NonNull PairingPrivateKey privateKey, @NonNull PairingPublicKey publicKey) {
    public PairingKeyPair {
        Objects.requireNonNull(privateKey, "privateKey cannot be null");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");
    }
}
