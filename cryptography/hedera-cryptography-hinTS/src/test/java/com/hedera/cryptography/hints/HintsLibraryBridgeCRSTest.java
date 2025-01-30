// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class HintsLibraryBridgeCRSTest {
    private static final HintsLibraryBridge INSTANCE = HintsLibraryBridge.getInstance();

    private static final int CRS_4_LENGTH = 1456;

    private static final int CONTRIBUTION_PROOF_LENGTH = 128;

    private byte[] initAndVerifyCRS() {
        final byte[] crs = INSTANCE.initCRS(4);

        assertNotNull(crs);
        assertEquals(CRS_4_LENGTH, crs.length);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        return crs;
    }

    @Test
    void testInitCRS() {
        initAndVerifyCRS();
    }

    private byte[] updateAndVerifyCRS(final byte[] prevCRS) {
        final byte[] nextCRSandContributionProof = INSTANCE.updateCRS(prevCRS, CRSConstants.RANDOM);

        assertNotNull(nextCRSandContributionProof);
        assertEquals(CRS_4_LENGTH + CONTRIBUTION_PROOF_LENGTH, nextCRSandContributionProof.length);

        // The ContributionProof is random by design, so we can only check the nextCRS which is deterministic
        // given the constant prevCRS and randomness inputs in the updateCRS call above:
        final byte[] nextCRS = Arrays.copyOf(nextCRSandContributionProof, CRS_4_LENGTH);
        assertArrayEquals(CRSConstants.UPDATED_CRS_4, nextCRS);

        return nextCRSandContributionProof;
    }

    @Test
    void testUpdateCRS() {
        final byte[] prevCRS = initAndVerifyCRS();

        updateAndVerifyCRS(prevCRS);
    }

    @Test
    void testVerifyCRS() {
        final byte[] prevCRS = initAndVerifyCRS();
        final byte[] nextCRSandContributionProof = updateAndVerifyCRS(prevCRS);

        final byte[] nextCRS = Arrays.copyOf(nextCRSandContributionProof, CRS_4_LENGTH);
        final byte[] contributionProof =
                Arrays.copyOfRange(nextCRSandContributionProof, CRS_4_LENGTH, nextCRSandContributionProof.length);

        assertTrue(INSTANCE.verifyCRS(prevCRS, nextCRS, contributionProof));
    }
}
