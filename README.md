# Hedera BLS Cryptography

This repository is separated into three main parts:

1. A set of public interfaces representing BLS concepts, in the `hedera-bls-api` module
    - The `BLSLoader` in this module allows an implementation of `BilinearMap` to be loaded from the
      java classpath
    - The `BilinearMap` returned from `BLSLoader` provides an entry point to a complete BLS
      signature scheme
2. An implementation of these public interfaces, in the `hedera-bls-impl` module
    - This implementation is exported so that consumers can have it in their java classpath, but it
      should only be interacted with via the public interface
    - The `Bls12381Bindings` class forms the java side of a JNI interface, to access the underlying
      cryptography implementation
    - The `LibraryLoader` utility class is responsible for loading compiled native code, produced in
      the `hedera-bls-rust-jni` module
3. A rust JNI interface, in the `hedera-bls-rust-jni` module
    - This module includes the rust side of a JNI interface
    - It serves to allow the `hedera-bls-impl` module to interact with
      the [zkcrypto BLS12_381](https://github.com/zkcrypto/bls12_381) rust library

# Building

The project is built with Gradle.

## Requirements

For the rust (cross-)compilation, you need to install `rustup`, `zig` and `lld`. On Mac, you can do that via:

```
brew install rustup zig lld
```

## Build the project

```
./gradlew build
```
