enum class RustTriplet(val triplet: String) {
    MACOS_AARCH64("aarch64-apple-darwin"),
    MACOS_X64("x86_64-apple-darwin"),
    WINDOWS_X64("x86_64-pc-windows-gnu"),
    WINDOWS_X86("i686-pc-windows-gnu"),
    LINUX_X64("x86_64-unknown-linux-gnu"),
    LINUX_X86("i686-unknown-linux-gnu"),
    LINUX_AARCH64("aarch64-unknown-linux-gnu")
}
