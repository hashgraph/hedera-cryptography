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

package com.hedera.cryptography.bls;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.pairings.api.Curve;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class BlsAggregationTest {

    @Test
    void test() {
        var schema = SignatureSchema.create(Curve.ALT_BN128, GroupAssignment.SHORT_PUBLIC_KEYS);
        var pairs = List.of(
                BlsKeyPair.generate(schema, new Random()),
                BlsKeyPair.generate(schema, new Random()),
                BlsKeyPair.generate(schema, new Random()),
                BlsKeyPair.generate(schema, new Random()));

        var msg =
                """
                    From Wikipedia, the free encyclopedia
                    This article is about plants in the family Araliaceae. For the typographic ornamentation ❧, see Fleuron (typography). For Hedera Hashgraph, see Hashgraph.
                    "Ivy" redirects here. For other plants, see list of plants known as ivy. For other uses, see Ivy (disambiguation).
                    Not to be confused with Hadera.
                    Hedera, commonly called ivy (plural ivies), is a genus of 12–15 species of evergreen climbing or ground-creeping woody plants in the family Araliaceae, native to Western Europe, Central Europe, Southern Europe, Macaronesia, northwestern Africa and across central-southern Asia east to Japan and Taiwan. Several species are cultivated as climbing ornamentals, and the name ivy especially denotes common ivy (Hedera helix), known in North America as "English ivy", which is frequently planted to clothe brick walls.
                    """
                        .getBytes(StandardCharsets.UTF_8);

        var signatures = pairs.stream().map(p -> p.privateKey().sign(msg)).toList();
        var publicKeys = pairs.stream().map(BlsKeyPair::publicKey).toList();
        for (int i = 0; i < signatures.size(); i++) {
            var signature = signatures.get(i);
            var publicKey = publicKeys.get(i);
            assertTrue(signature.verify(publicKey, msg));
        }

        var aggregatedPk = BlsPublicKey.aggregate(publicKeys);
        var aggregateSignature = BlsSignature.aggregate(signatures);
        assertTrue(aggregateSignature.verify(aggregatedPk, msg));
    }
}
