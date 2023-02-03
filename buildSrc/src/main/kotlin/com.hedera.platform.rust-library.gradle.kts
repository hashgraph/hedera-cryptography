import gradle.kotlin.dsl.accessors._01a7fddcf81aa279b379d6fe3cb64505.build
import gradle.kotlin.dsl.accessors._01a7fddcf81aa279b379d6fe3cb64505.clean

/*
 * Copyright 2016-2022 Hedera Hashgraph, LLC
 *
 * This software is the confidential and proprietary information of
 * Hedera Hashgraph, LLC. ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Hedera Hashgraph.
 *
 * HEDERA HASHGRAPH MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. HEDERA HASHGRAPH SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 */

plugins {
    base
}

val rustLibrary by configurations.creating {
    isCanBeResolved = false
    isCanBeConsumed = true
    isVisible = true

    attributes {
        attribute(LibraryElements.LIBRARY_ELEMENTS_ATTRIBUTE, project.objects.named("rust-library"))
    }
}

val compileRust = tasks.create<RustCompileTask>("compileRust")
val cleanRust = tasks.create<RustCleanTask>("cleanRust")

tasks.assemble {
    dependsOn(compileRust)
}

tasks.clean {
    dependsOn(cleanRust)
}

artifacts {
    add(rustLibrary.name, compileRust.outputFile) {
        builtBy(compileRust)
    }
}

