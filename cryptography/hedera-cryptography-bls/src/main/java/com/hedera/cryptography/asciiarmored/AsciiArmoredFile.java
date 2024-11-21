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

package com.hedera.cryptography.asciiarmored;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Objects;

/**
 * A parsed Ascii armored file
 *
 * @param contents the contents of the file
 * @param asciiArmoredType  the type of the file
 */
public record AsciiArmoredFile(@NonNull String contents, @NonNull AsciiArmoredType asciiArmoredType) {
    /** Creates a new instance of this class */
    public AsciiArmoredFile {
        Objects.requireNonNull(contents, "contents must not be null");
        Objects.requireNonNull(asciiArmoredType, "asciiArmoredType must not be null");
    }
}
