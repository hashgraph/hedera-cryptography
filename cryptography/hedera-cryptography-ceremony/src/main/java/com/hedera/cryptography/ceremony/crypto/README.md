This is a refactored copy of com.swirlds.platform.crypto .
Since we need to load node keys and certs in order to create a signed certificate for our own generated key pair,
we want to use the exact same code that the Consensus Node uses to load its keys.
