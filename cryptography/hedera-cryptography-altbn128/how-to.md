# Compilation

## Mac
Install `rustup` and `zig`

```bash
  brew install rustup zig
```

# How to compile

Compile is done as part of the Gradle build. For example:

```bash
  ./gradlew assemble
```

creates all Jar files, which contain the compiled libraries

To only do the rust compilation for all targets, you may run:

```bash
  ./gradlew cargoBuild
```

# Use with intellij

## Install rust support for intellij:

* follow: https://www.jetbrains.com/help/idea/rust-plugin.html#run
* Open: [Cargo.toml](Cargo.toml)
* Attach to cargo: ![img.png](img.png)
