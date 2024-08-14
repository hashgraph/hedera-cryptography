/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hedera.cryptography.altbn128;

import com.hedera.cryptography.pairings.api.BilinearPairing;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collection;

public class AltBn128Group1 implements Group {

    private final AltBn128BilinearPairing pairing;

    public AltBn128Group1(@NonNull final AltBn128BilinearPairing pairing) {this.pairing = pairing;}

    @NonNull
    @Override
    public BilinearPairing getPairing() {
        return pairing;
    }

    @NonNull
    @Override
    public GroupElement getGenerator() {
        return null;
    }

    @NonNull
    @Override
    public GroupElement zeroElement() {
        return null;
    }

    @NonNull
    @Override
    public GroupElement randomElement(@NonNull final byte[] seed) {
        return null;
    }

    @NonNull
    @Override
    public GroupElement elementFromHash(@NonNull final byte[] input) {
        return null;
    }

    @NonNull
    @Override
    public GroupElement batchAdd(@NonNull final Collection<GroupElement> elements) {
        return null;
    }

    @NonNull
    @Override
    public GroupElement elementFromBytes(@NonNull final byte[] bytes) {
        return null;
    }

    @Override
    public int getCompressedSize() {
        return 0;
    }

    @Override
    public int getUncompressedSize() {
        return 0;
    }

    @Override
    public int getSeedSize() {
        return 0;
    }
}
