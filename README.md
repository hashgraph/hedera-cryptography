[![Made With](https://img.shields.io/badge/made_with-java-blue)](https://github.com/hashgraph/hedera-cryptography/)
[![Made With](https://img.shields.io/badge/rust-green)](https://github.com/hashgraph/hedera-cryptography)
[![License](https://img.shields.io/badge/license-apache2-blue.svg)](LICENSE)
# Hedera Cryptography

## Description
This section is a work in progress.

The repository includes the following projects:
* **cryptography/hedera-cryptography-pairings-api**: API that defines the generic set of primitives to work with Elliptic Curves and pairing-based cryptography.
* **cryptography/hedera-cryptography-albn128**: Implementation of _hedera-cryptography-pairings-api_ using the BN254 (also known as alt-BN128) Elliptic Curve.
* **cryptography/hedera-cryptography-bls**: Library that allows the creation of BLS keys and signatures. It works under using a runtime implementation of pairings api.
* **cryptography/hedera-cryptography-tss**: Library implementing the primitives for operating with a threshold-signature-scheme. The [Groth21](https://eprint.iacr.org/2021/339) algorithm was chosen because it is efficient for use in smart
  contract verification, and we can assign a multiplicity of shares to nodes to get close enough in modeling the
  distribution of weight between nodes. It is based off of prototypes developed by [Rohit Sinha](https://github.com/rsinha),
* **common/hedera-common-nativesupport**: A Helper library providing support for working with jni and external libraries.

For the proposal that originated the work in this repository see:
[Tss-Library](https://github.com/hashgraph/hedera-services/blob/develop/platform-sdk/docs/proposals/TSS-Library/TSS-Library.md)


## Build
The project is built with Gradle.

### Requirements

For the rust (cross-)compilation, you need to install `rustup`, `zig` and `lld`. On Mac, you can do that via:

```
brew install rustup zig lld
rustup target add x86_64-pc-windows-msvc
```

### Build the project

```
./gradlew build
```

## Support

If you have a question on how to use the product, please see our
[support guide](https://github.com/hashgraph/.github/blob/main/SUPPORT.md).

## Contributing

Contributions are welcome. Please see the
[contributing guide](https://github.com/hashgraph/.github/blob/main/CONTRIBUTING.md) to see how you
can get involved.

## Code of Conduct

This project is governed by the
[Contributor Covenant Code of Conduct](https://github.com/hashgraph/.github/blob/main/CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code of conduct.

## License

[Apache License 2.0](LICENSE)
