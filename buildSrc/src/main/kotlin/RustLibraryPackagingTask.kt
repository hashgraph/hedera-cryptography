import gradle.kotlin.dsl.accessors._6b5a012da99913209253918e0907799b.sourceSets
import gradle.kotlin.dsl.accessors._6ca76b4a0a5e09fb29b07b0b7dae9905.main
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction

abstract class RustLibraryPackagingTask : DefaultTask() {
    @InputFiles
    val configuration: ConfigurableFileCollection = project.objects.fileCollection()

    @TaskAction
    fun execute() {
        val resourceFolder = project.sourceSets.main.get().resources.sourceDirectories.first()
        configuration.files.first().copyRecursively(resourceFolder, true)
    }
}

