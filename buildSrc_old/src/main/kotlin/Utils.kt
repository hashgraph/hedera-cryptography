import net.swiftzer.semver.SemVer
import org.gradle.api.Project
import java.io.File
import java.io.OutputStream
import java.io.PrintStream
import java.util.*

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

class Utils {
    companion object {
        @JvmStatic
        fun updateVersion(project: Project, newVersion: SemVer) {
            val gradlePropFile = File(project.projectDir, "gradle.properties")
            val props = Properties()

            if (gradlePropFile.exists()) {
                props.load(gradlePropFile.inputStream())
            }

            props.setProperty("version", newVersion.toString())
            props.store(gradlePropFile.bufferedWriter(), null)
        }

        @JvmStatic
        fun generateProjectVersionReport(rootProject: Project, ostream: OutputStream) {
            val writer = PrintStream(ostream, false, Charsets.UTF_8)

            ostream.use {
                writer.use {
                    // Writer headers
                    writer.println("### Deployed Version Information")
                    writer.println()
                    writer.println("| Artifact Name | Version Number |")
                    writer.println("| --- | --- |")

                    // Write table rows
                    rootProject.childProjects.values.onEach {
                        writer.printf("| %s | %s |\n", it.name, it.version.toString())
                    }
                    writer.flush()
                    ostream.flush()
                }
            }
        }
    }
}
