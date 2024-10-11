package com.hedera.cryptography.pairings.signatures.api;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.pairings.api.Curve;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class PairingKeyPairTest {
    private static final SignatureSchema SIGNATURE_SCHEMA =
            SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_SIGNATURES);

    @Test
    public void generateTest() throws NoSuchAlgorithmException {
        // When
        final PairingKeyPair keyPair = PairingKeyPair.generate(SIGNATURE_SCHEMA);

        // then
        assertNotNull(keyPair);
        assertNotNull(keyPair.privateKey());
        assertNotNull(keyPair.publicKey());
    }

    @Test
    // since we are testing nullity, we are suppressing the warning of passing null
    @SuppressWarnings("ConstantConditions")
    public void nullityChecksTest() {
        assertThrows(NullPointerException.class, () -> new PairingKeyPair(null, null));
        assertThrows(NullPointerException.class, () -> new PairingKeyPair(null, Mockito.mock(PairingPublicKey.class)));
        assertThrows(NullPointerException.class, () -> new PairingKeyPair(Mockito.mock(PairingPrivateKey.class), null));
        assertThrows(NullPointerException.class, () -> PairingKeyPair.generate(null));
    }
}