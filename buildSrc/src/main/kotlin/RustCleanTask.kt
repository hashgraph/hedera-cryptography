import org.gradle.api.DefaultTask
import org.gradle.api.tasks.TaskAction

abstract class RustCleanTask : DefaultTask {

    constructor() {
        group = "build"
    }

    @TaskAction
    fun execute() {
        Rust.clean(project)
    }
}
