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

package com.hedera.cryptography.utils.test.fixtures.rng;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import jakarta.inject.Inject;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.junit.jupiter.api.extension.TestWatcher;

/**
 * A JUnit 5 extension that can be used to inject a {@link Random} instance into a test method or test class. Tests that
 * are annotated with this extension will have access to a {@link Random} instance that can be used to generate random
 * values.
 * <ul>
 *     <li>The {@link Random} instance is created with a random seed which is printed to the console.</li>
 *     <li>The {@link Random} instance can be injected into a test method or test class by annotating a field with
 *     {@link Inject} and of type {@link Random}.</li>
 *     <li>The {@link Random} instance can be injected into a test method by adding a parameter of type {@link Random}.</li>
 * </ul>
 */
public class RngExtension implements InvocationInterceptor, ParameterResolver, TestWatcher {

    /**
     * The namespace of the extension.
     */
    private static final Namespace EXTENSION_NAMESPACE = Namespace.create(RngExtension.class);

    /**
     * The key to store the seed in the extension context.
     */
    private static final String SEED_KEY = "seed";

    /**
     * Creates a new {@link SeededRandom} instance with a random seed which gets stored in the extension context.
     *
     * @param extensionContext the extension context of the test
     * @return a new {@link SeededRandom} instance
     */
    private SeededRandom createRandomWithSeed(final ExtensionContext extensionContext) {
        final long seed = new Random().nextLong();
        final SeededRandom random = new SeededRandom(seed);

        extensionContext.getStore(EXTENSION_NAMESPACE).put(SEED_KEY, seed);

        return random;
    }

    /**
     * Intercepts a test method invocation and injects a {@link SeededRandom} instance into the test instance. The
     * {@link SeededRandom} instance is injected into any field of the test instance that is annotated with
     * {@link Inject} and is of type {@link SeededRandom}.
     *
     * @param invocation       the invocation which allows to proceed with the test method execution
     * @param ignored          the reflective invocation context of the test method (ignored)
     * @param extensionContext the extension context of the test
     * @throws Throwable if an error occurs during the interception
     */
    @Override
    public void interceptTestMethod(
            final Invocation<Void> invocation,
            final ReflectiveInvocationContext<Method> ignored,
            final ExtensionContext extensionContext)
            throws Throwable {
        Objects.requireNonNull(invocation, "invocation must not be null");
        Objects.requireNonNull(extensionContext, "extensionContext must not be null");

        final Class<?> testClass = extensionContext.getRequiredTestClass();
        Arrays.stream(testClass.getDeclaredFields())
                .filter(field -> !Modifier.isFinal(field.getModifiers()))
                .filter(field -> !Modifier.isStatic(field.getModifiers()))
                .filter(field -> field.isAnnotationPresent(Inject.class))
                .filter(field -> Objects.equals(field.getType(), Random.class))
                .forEach(field -> {
                    try {
                        field.setAccessible(true);
                        field.set(extensionContext.getRequiredTestInstance(), createRandomWithSeed(extensionContext));
                    } catch (Exception ex) {
                        throw new RuntimeException("Error in injection", ex);
                    }
                });
        invocation.proceed();
    }

    /**
     * Checks if this extension supports parameter resolution for the given parameter context.
     *
     * @param parameterContext the context of the parameter to be resolved
     * @param ignored          the extension context of the test (ignored)
     * @return true if parameter resolution is supported, false otherwise
     * @throws ParameterResolutionException if an error occurs during parameter resolution
     */
    @Override
    public boolean supportsParameter(
            @NonNull final ParameterContext parameterContext, @Nullable final ExtensionContext ignored)
            throws ParameterResolutionException {
        Objects.requireNonNull(parameterContext, "parameterContext must not be null");

        return Optional.of(parameterContext)
                .map(ParameterContext::getParameter)
                .map(Parameter::getType)
                .filter(Random.class::isAssignableFrom)
                .isPresent();
    }

    /**
     * Resolves the parameter of a test method, providing a {@link SeededRandom} instance when needed.
     *
     * @param parameterContext the context of the parameter to be resolved
     * @param extensionContext the extension context of the test
     * @return the resolved parameter value
     * @throws ParameterResolutionException if an error occurs during parameter resolution
     */
    @Override
    public Object resolveParameter(
            @NonNull final ParameterContext parameterContext, @NonNull final ExtensionContext extensionContext)
            throws ParameterResolutionException {
        Objects.requireNonNull(parameterContext, "parameterContext must not be null");
        Objects.requireNonNull(extensionContext, "extensionContext must not be null");

        return Optional.of(parameterContext)
                .map(ParameterContext::getParameter)
                .map(Parameter::getType)
                .filter(t -> t.equals(Random.class) || t.equals(SeededRandom.class))
                .map(t -> createRandomWithSeed(extensionContext))
                .orElseThrow(() -> new ParameterResolutionException("Could not resolve parameter"));
    }

    /**
     * Invoked after a test has been executed and failed.
     *
     * @param extensionContext the current extension context; never {@code null}
     * @param cause            the throwable that caused test failure; may be {@code null}
     */
    @Override
    public void testFailed(@NonNull final ExtensionContext extensionContext, @Nullable final Throwable cause) {
        Objects.requireNonNull(extensionContext, "extensionContext must not be null");
        final Long seed = extensionContext.getStore(EXTENSION_NAMESPACE).get(SEED_KEY, Long.class);
        if (seed != null) {
            System.out.println("Test " + extensionContext.getDisplayName() + " failed with seed: " + seed);
        }
        clear(extensionContext);
    }

    /**
     * Invoked after a test has been executed and succeeded.
     *
     * @param extensionContext the current extension context; never {@code null}
     */
    @Override
    public void testSuccessful(@NonNull final ExtensionContext extensionContext) {
        Objects.requireNonNull(extensionContext, "extensionContext must not be null");
        clear(extensionContext);
    }

    /**
     * Removes the seed from the extension context.
     *
     * @param extensionContext the current extension context; never {@code null}
     */
    private static void clear(@NonNull final ExtensionContext extensionContext) {
        extensionContext.getStore(EXTENSION_NAMESPACE).remove(SEED_KEY);
    }
}
