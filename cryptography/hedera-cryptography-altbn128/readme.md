# Add support
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustup target add x86_64-unknown-linux-gnu
```
Also
```bash
  brew install zig

```

# How to compile

```bash
  cargo zigbuild --target aarch64-unknown-linux-gnu --target x86_64-apple-darwin --target aarch64-apple-darwin --target aarch64-unknown-linux-gnu --target x86_64-unknown-linux-gnu
  cargo build --target x86_64-pc-windows-gnu
 ```
