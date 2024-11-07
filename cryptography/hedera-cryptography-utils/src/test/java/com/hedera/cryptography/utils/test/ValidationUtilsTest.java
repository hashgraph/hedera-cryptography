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

package com.hedera.cryptography.utils.test;

import static org.junit.jupiter.api.Assertions.*;

import com.hedera.cryptography.utils.ValidationUtils;
import org.junit.jupiter.api.Test;

class ValidationUtilsTest {

    @Test
    void testInvalidInheritance() {
        assertThrows(IllegalArgumentException.class, () -> ValidationUtils.expectOrThrow(Dog.class, new Cat()));
        assertThrows(IllegalArgumentException.class, () -> ValidationUtils.expectOrThrow(Dog.class, new Animal()));
    }

    @Test
    void testValidInheritance() {
        assertDoesNotThrow(() -> ValidationUtils.expectOrThrow(Animal.class, new Animal()));
        assertDoesNotThrow(() -> ValidationUtils.expectOrThrow(Animal.class, new Dog()));
        assertDoesNotThrow(() -> ValidationUtils.expectOrThrow(Animal.class, new Cat()));
        assertDoesNotThrow(() -> ValidationUtils.expectOrThrow(Dog.class, new Dog()));
    }

    static class Animal {}

    static class Dog extends Animal {}

    static class Cat extends Animal {}
}
