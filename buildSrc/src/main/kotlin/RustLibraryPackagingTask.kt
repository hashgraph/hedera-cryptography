import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.*

abstract class RustLibraryPackagingTask : DefaultTask() {
    @InputFiles
    val configuration: ConfigurableFileCollection = project.objects.fileCollection()

    @InputDirectory
    val resourceFolder: DirectoryProperty = project.objects.directoryProperty()

    @TaskAction
    fun execute() {
        configuration.files.first().copyRecursively(resourceFolder.asFile.get(), true)
    }
}

