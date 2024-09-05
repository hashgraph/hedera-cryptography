package com.hedera.cryptography.pairings.signatures.api;

import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.Objects;

class ValidationUtils {

    public static SignatureSchema getAndValidateSignatureSchema(final @Nullable byte[] bytes) {
        if(Objects.requireNonNull(bytes, "bytes must not be null").length ==0)
            throw new IllegalArgumentException("bytes must not be empty");
        return SignatureSchema.create(bytes[0]);
    }

}
