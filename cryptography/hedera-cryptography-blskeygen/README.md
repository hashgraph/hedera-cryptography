# BlsKeyGen Module

## Introduction
The KeyGen Tool Module is designed for key generation based on the ALT_BN128 curve.
The keys are saved directly into PEM files.

The keys will not be produced if there is a previously existing file in the requested location.
## Usage
The KeyGen tool is used from the command line. Here are the main commands:

### Compile and run
Generate Distribution tar file
```bash

    ./gradlew :hedera-cryptography-blskeygen:distTar
```
unzip `build/distributions/hedera-cryptography-blskeygen-0.1.0-SNAPSHOT.tar`
locate file `hedera-cryptography-eckeygen` in unziped folder: `build/distributions/hedera-cryptography-blskeygen-0.1.0-SNAPSHOT/bin`


### Help:
Display usage information.
```bash
hedera-cryptography-blskeygen --help
```

### Generating a Key Pair:
Generate a private and public key pair and save them to specified PEM files.

```bash
hedera-cryptography-blskeygen generate-keys path/to/privateKey.pem path/to/publicKey.pem
```

### Generating a Public Key from an Existing Private Key:
Generate a public key from an existing private key PEM file.
```bash
hedera-cryptography-blskeygen generate-public-key path/to/privateKey.pem path/to/publicKey.pem
```
