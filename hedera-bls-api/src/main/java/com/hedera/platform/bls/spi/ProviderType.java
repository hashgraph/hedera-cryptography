/*
 * Copyright (C) 2023 Hedera Hashgraph, LLC
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
package com.hedera.platform.bls.spi;

/**
 * The different possible types of {@link BilinearMapProvider}
 */
public enum ProviderType {
    /**
     * A provider capable of providing an implementation suitable for production runtime usage
     */
    RUNTIME,
    /**
     * A provider for an experimental implementation
     */
    EXPERIMENTAL,
    /**
     * A provider which returns an implementation with mocked behavior
     */
    MOCK,
    /**
     * A provider which returns a simple stubbed implementation
     */
    STUB
}
