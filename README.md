# Hedera BLS Cryptography

This repository is a Java wrapper around the [zkcrypto](https://github.com/zkcrypto/bls12_381) Rust implementation of
the BLS12-381 pairing-friendly elliptic curve construction.
<p>
This repository is separated into two main parts:

1. An interface between Java and Rust, to be able to access the underlying implementation in the zkcrypto library
    - The Rust side of the interface can be found in the `hedera-bls-rust-jni` module
    - The Java side of the interface can be found in `BLS12381Bindings` in the `hedera-bls-api` module
    - The `LibraryLoader` class is responsible for loading the rust library and setting up the bindings
2. A set of Java objects representing the BLS cryptographic primitives needed by Hedera
    - These primitives are in the `hedera-bls-api` module
    - These objects call into the Java/Rust interface to perform their function
