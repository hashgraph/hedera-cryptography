import com.moandjiezana.toml.Toml
import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.Project
import org.gradle.api.tasks.StopExecutionException
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.stream.Collectors

class Rust {
    companion object {
        private const val LINUX_MAC_EXECUTABLE: String = "cargo"
        private const val WINDOWS_EXECUTEABLE: String = "cargo.exe"

        @JvmStatic
        fun selectTriplet(): RustTriplet {
            for (it in RustTriplet.values()) {
                if (Os.isFamily(it.operatingSystem) && Os.isArch(it.architecture)) {
                    if (it.operatingSystem.equals(Os.FAMILY_UNIX) && Os.isFamily(Os.FAMILY_MAC)) {
                        continue
                    }

                    return it
                }
            }

            throw StopExecutionException("Cannot execute Cargo: No matching triplets found!")
        }

        @JvmStatic
        fun compile(project: Project, triplet: RustTriplet) {
            val command: String = if (Os.isFamily(Os.FAMILY_WINDOWS)) WINDOWS_EXECUTEABLE else LINUX_MAC_EXECUTABLE
            project.logger.warn(" >> Building Library for Triplet => {}", triplet.identifier)
            project.exec({
                workingDir(project.projectDir)
                commandLine(command)
                args("build", "--release", "--target", triplet.identifier)
            }).assertNormalExitValue()
        }

        @JvmStatic
        fun clean(project: Project) {
            val command: String = if (Os.isFamily(Os.FAMILY_WINDOWS)) WINDOWS_EXECUTEABLE else LINUX_MAC_EXECUTABLE
            project.exec({
                workingDir(project.projectDir)
                commandLine(command)
                args("clean")
            }).assertNormalExitValue()
        }

        @JvmStatic
        fun readCargoLibraryName(manifest: File): String {
            val inputStream = Files.newInputStream(manifest.toPath())
            inputStream.use {
                val toml: Toml = Toml().read(it)
                return toml.getString("lib.name")
            }
        }

        @JvmStatic
        fun predictArtifactPath(project: Project, triplet: RustTriplet, libraryName: String): File {
            val cargoBuildPath = Path.of(project.projectDir.path, "target", triplet.identifier, "release")
            val artifactName = "${triplet.filePrefix}${libraryName}.${triplet.fileExtension}"

            return cargoBuildPath.resolve(artifactName).toFile()
        }
    }
}
