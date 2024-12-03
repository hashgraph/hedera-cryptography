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

package com.hedera.cryptography.testfixtures.altbn128;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * A tool to load externally produced altbn128 information from a json file.
 */
public class AltBn128ExternalData {
    /**
     * The parsed json data stored in memory
     */
    private final Map<String, Object> data;

    /**
     * Constructor
     */
    public AltBn128ExternalData() {
        var data = AltBn128ExternalData.class.getClassLoader().getResourceAsStream("altbn128_ext_data.json");
        var gson = new Gson();
        Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
        this.data = gson.fromJson(new InputStreamReader(data), mapType);
    }

    /**
     * Returns a list fo scalars generated with an external library.
     * @return a list of scalars of altbn128
     */
    public List<BigInteger> getScalars() {
        var sksValues = (List<String>) data.get("SCALARS");
        return sksValues.stream().map(BigInteger::new).toList();
    }

    /**
     * Returns a list of g1 points generated with an external library.
     * @return a list of g1 points generated with an external library.
     */
    public List<List<BigInteger[]>> getG1Points() {
        return groups("GROUP1");
    }

    /**
     * Returns a list of g2 points generated with an external library.
     * @return a list of g2 points generated with an external library.
     */
    public List<List<BigInteger[]>> getG2Points() {
        return groups("GROUP2");
    }

    private List<List<BigInteger[]>> groups(final @NonNull String group) {
        var pksValues = (List<List<String>>) data.get(group);
        return pksValues.stream()
                .map(v -> v.stream().map(BigInteger::new).toList())
                .map(v -> Stream.of(
                                v.subList(0, v.size() / 2).toArray(BigInteger[]::new),
                                v.subList(v.size() / 2, v.size()).toArray(BigInteger[]::new))
                        .toList())
                .toList();
    }
}
