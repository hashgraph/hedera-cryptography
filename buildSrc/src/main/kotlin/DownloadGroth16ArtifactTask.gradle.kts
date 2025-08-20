// SPDX-License-Identifier: Apache-2.0
import java.net.URI
import org.gradle.api.internal.file.FileOperations

// Support the ProofCompressorTest by preparing a large binary artifact that the compressor uses:
val groth16ArtifactDir = layout.buildDirectory.dir("groth16-artifact")

abstract class DownloadGroth16ArtifactTask : DefaultTask() {
    @get:Inject protected abstract val files: FileOperations

    @get:OutputDirectories abstract val groth16Dir: DirectoryProperty

    @TaskAction
    fun action() {
        val out = groth16Dir.get().dir("v5.0.0")
        files.mkdir(out)

        // This is a 3GB download, so we only do this if we must:
        val filename = "v5.0.0-groth16.tar.gz"
        val uri = "https://builds.hedera.com/tss/sp1/groth16/v5.0/$filename"
        val url = URI(uri).toURL()
        val tarball = groth16Dir.get().file(filename).asFile
        if (!tarball.exists()) {
            println("Downloading $uri to ${tarball.absolutePath}")
            // file.writeBytes(url.readBytes()) runs out of heap space, so we copy streams instead:
            url.openStream().use { input ->
                tarball.outputStream().use { output -> input.copyTo(output) }
            }
        } else {
            println("$uri has already been downloaded as: ${tarball.absolutePath}")
        }
        // Just one of the artifact files, good enough for a quick test:
        val testArtifactFileName = "groth16_circuit.bin"
        if (!files.file(out.file(testArtifactFileName)).exists()) {
            println("Extracting ${tarball.absolutePath} to ${out.asFile.absolutePath}")
            files.sync {
                from(files.tarTree(tarball))
                into(out)
            }
        } else {
            println(
                "Not extracting Groth16 artifact as it already exists: e.g. ${out.file(testArtifactFileName).asFile.absolutePath}"
            )
        }
    }
}

tasks.register<DownloadGroth16ArtifactTask>("downloadGroth16ArtifactTask") {
    groth16Dir.convention(groth16ArtifactDir)
}
