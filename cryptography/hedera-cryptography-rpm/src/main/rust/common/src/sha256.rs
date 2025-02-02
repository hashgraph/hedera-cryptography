use sha2::{Digest, Sha256};

pub fn digest_sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(data.as_ref());
    // read hash digest and consume hasher
    let result: [u8; 32] = hasher.finalize().into();

    result
}