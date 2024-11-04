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

package com.hedera.common.testfixtures;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.lang.reflect.Parameter;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

public class RngExtension implements InvocationInterceptor, ParameterResolver {

    private Random createRandom() {
        final Random random = new Random();
        int seed = random.nextInt();
        System.out.println("Random seed: " + seed);
        return new Random(seed);
    }

    @Override
    public boolean supportsParameter(
            @NonNull final ParameterContext parameterContext, @Nullable final ExtensionContext extensionContext)
            throws ParameterResolutionException {
        Objects.requireNonNull(parameterContext, "parameterContext must not be null");

        return Optional.of(parameterContext)
                .map(ParameterContext::getParameter)
                .map(Parameter::getType)
                .filter(Random.class::isAssignableFrom)
                .isPresent();
    }

    @Override
    public Object resolveParameter(
            @NonNull final ParameterContext parameterContext, @Nullable final ExtensionContext extensionContext)
            throws ParameterResolutionException {
        Objects.requireNonNull(parameterContext, "parameterContext must not be null");

        return Optional.of(parameterContext)
                .map(ParameterContext::getParameter)
                .map(Parameter::getType)
                .filter(t -> t.equals(Random.class))
                .map(t -> createRandom())
                .orElseThrow(() -> new ParameterResolutionException("Could not resolve parameter"));
    }
}
