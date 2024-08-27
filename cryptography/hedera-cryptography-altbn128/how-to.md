# Compilation

Install rustup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
## Mac
Install the cross-compiler
```bash
  brew install zig
```

# How to compile
## Manually
Fist line compiles for all platforms that zigbuild has support:
```bash
  cargo zigbuild --target aarch64-unknown-linux-gnu --target x86_64-apple-darwin --target aarch64-apple-darwin --target aarch64-unknown-linux-gnu --target x86_64-unknown-linux-gnu --release
 ```

Last one is windows that cannot be compiled with zig, but it can be compiled directly with rust
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --target x86_64-pc-windows-gnu
 ```
## Using script [compile.sh](compile.sh)

```bash
./compile.sh
 ```

# Use with intellij

## Install rust support for intellij:

* follow: https://www.jetbrains.com/help/idea/rust-plugin.html#run
* Open: [Cargo.toml](Cargo.toml)
* Attach to cargo: ![img.png](img.png)
