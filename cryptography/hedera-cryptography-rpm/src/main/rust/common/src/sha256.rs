use sha2::{Digest, Sha256};

pub const HASH_LENGTH: usize = 32;

pub fn digest_sha256(data: impl AsRef<[u8]>) -> [u8; HASH_LENGTH] {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(data.as_ref());
    // read hash digest and consume hasher
    let result: [u8; HASH_LENGTH] = hasher.finalize().into();

    result
}