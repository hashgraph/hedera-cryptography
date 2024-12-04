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

package com.hedera.cryptography.bls.test.fixtures;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * A tool to load externally produced altbn128 information from a json file.
 */
public class AltBn128ExternalData {
    private static final String SCALARS = "SCALARS";
    private static final String G1 = "GROUP1";
    private static final String G2 = "GROUP2";
    private static final String NONG2 = "E2_non_G2";
    private static final String FILE_NAME = "altbn128_ext_data.json";

    /**
     * The parsed json data stored in memory
     */
    private final Map<String, Object> data;

    /**
     * Constructor
     */
    public AltBn128ExternalData() {
        final var data = AltBn128ExternalData.class.getClassLoader().getResourceAsStream(FILE_NAME);
        if (data == null) {
            throw new IllegalStateException("Could not find data json file");
        }
        final var gson = new Gson();
        final var mapType = new TypeToken<Map<String, Object>>() {}.getType();
        this.data = gson.fromJson(new InputStreamReader(data), mapType);
    }

    /**
     * Returns a list fo scalars generated with an external library.
     * @return a list of scalars of altbn128
     */
    @SuppressWarnings("unchecked")
    public List<BigInteger> getScalars() {
        var sksValues = (List<String>) data.get(SCALARS);
        return sksValues.stream().map(BigInteger::new).toList();
    }

    /**
     * Returns a list of g1 points generated with an external library.
     * @return a list of g1 points generated with an external library.
     */
    public List<Coordinate> getG1Points() {
        return coordinates(G1);
    }

    /**
     * Returns a list of g2 points generated with an external library.
     * @return a list of g2 points generated with an external library.
     */
    public List<Coordinate> getG2Points() {
        return coordinates(G2);
    }

    /**
     * Returns a list of coordinates not in G2
     * @return a list of non g2 points.
     */
    public List<Coordinate> nonG2Points() {
        return coordinates(NONG2);
    }

    @SuppressWarnings("unchecked")
    private List<Coordinate> coordinates(final @NonNull String group) {
        var pksValues = (List<List<String>>) data.get(group);
        return pksValues.stream()
                .map(v -> v.stream().map(BigInteger::new).toList())
                .map(v -> new Coordinate(v.subList(0, v.size() / 2), v.subList(v.size() / 2, v.size())))
                .toList();
    }

    /**
     * X and y coordinates as group of bigIntegers
     * @param x x coordinate
     * @param y y coordinate
     */
    public record Coordinate(@NonNull List<BigInteger> x, @NonNull List<BigInteger> y) {}
}
