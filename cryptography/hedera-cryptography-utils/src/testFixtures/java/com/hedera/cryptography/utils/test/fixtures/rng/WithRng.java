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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Random;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * A JUnit 5 annotation that can be used to inject a {@link Random} into a test method or test class. Tests that
 * are annotated with this annotation will get a new instance of {@link Random} for each test method. And the seed
 * of the {@link Random} instance will be printed to the console. This is useful for debugging tests that are
 * non-deterministic.
 *
 * @see RngExtension
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(RngExtension.class)
public @interface WithRng {}
