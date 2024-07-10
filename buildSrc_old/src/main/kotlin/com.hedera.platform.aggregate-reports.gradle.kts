import net.swiftzer.semver.SemVer

plugins {
    `java-platform`
    id("lazy.zoo.gradle.git-data-plugin")
}

tasks.create("showVersion") {
    group = "versioning"
    doLast {
        println(project.version)
    }
}

tasks.create("versionAsPrefixedCommit") {
    group = "versioning"
    doLast {
        gitData.lastCommitHash?.let {
            val prefix = findProperty("commitPrefix")?.toString() ?: "adhoc"
            val newPrerel = prefix + ".x" + it.take(8)
            val currVer = SemVer.parse(project.version.toString())
            try {
                val newVer = SemVer(currVer.major, currVer.minor, currVer.patch, newPrerel)
                Utils.updateVersion(project, newVer)
            } catch (e: java.lang.IllegalArgumentException) {
                throw IllegalArgumentException(String.format("%s: %s", e.message, newPrerel), e)
            }
        }
    }
}

tasks.create("versionAsSnapshot") {
    group = "versioning"
    doLast {
        val currVer = SemVer.parse(project.version.toString())
        val newVer = SemVer(currVer.major, currVer.minor, currVer.patch, "SNAPSHOT")

        Utils.updateVersion(project, newVer)
    }
}

tasks.create("versionAsSpecified") {
    group = "versioning"
    doLast {
        val verStr = findProperty("newVersion")?.toString()

        if (verStr == null) {
            throw IllegalArgumentException("No newVersion property provided! Please add the parameter -PnewVersion=<version> when running this task.")
        }

        val newVer = SemVer.parse(verStr)
        Utils.updateVersion(project, newVer)
    }
}
