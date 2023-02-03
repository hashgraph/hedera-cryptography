import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.nio.file.Path

abstract class RustCompileTask : DefaultTask {

    @Internal
    val libraryName: Provider<String> = project.provider { Rust.readCargoLibraryName(cargoFile.asFile.get()) }

    @Internal
    val triplet: Provider<RustTriplet> = project.provider(Rust::selectTriplet)

    @InputFile
    val cargoFile: RegularFileProperty =
        project.objects.fileProperty().convention(project.layout.projectDirectory.file("Cargo.toml"))

    @OutputDirectory
    val outputFile: DirectoryProperty =
        project.objects.directoryProperty().fileValue(File(project.layout.buildDirectory.get().asFile.absoluteFile, "libs"))

    constructor() {
        group = "build"
    }

    @TaskAction
    fun execute() {
        Rust.compile(project, triplet.get())

        val sourceFile = Rust.predictArtifactPath(project, triplet.get(), libraryName.get())
        val destDirectory = Path.of(outputFile.get().asFile.absolutePath, triplet.get().classifier, triplet.get().architecture).toFile()
        destDirectory.mkdirs()
        sourceFile.copyTo(File(destDirectory, sourceFile.name), true)
    }
}
