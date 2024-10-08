package com.hedera.cryptography.eckeygen.pem;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

public record FileRead(@NonNull String contents, @NonNull PemType pemType) {
    public FileRead {
        Objects.requireNonNull(contents, "contents must not be null");
        Objects.requireNonNull(pemType, "pemType must not be null");
    }
}
