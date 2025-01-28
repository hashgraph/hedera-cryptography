use derive_more::derive::Deref;
use serde::{Deserialize, Serialize};
use serde_big_array::Array;

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;
pub const SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;

///////////

#[repr(transparent)]
#[derive(Debug, Deref, Clone)]
pub struct VerifyingKey(pub ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ()> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| ())
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let signature = <ed25519_dalek::Signature>::from_bytes(signature);
        self.0.verify_strict(message, &signature).is_ok()
    }
}

///////////

#[repr(transparent)]
#[derive(Debug, Deref, Clone)]
pub struct SigningKey(pub ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey =
            ed25519_dalek::SigningKey::generate(&mut csprng);
        Self(signing_key)
    }

    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::ed25519::signature::Signer;
        Signature(Array(self.0.sign(message).to_bytes()))
    }
}

///////////

#[repr(transparent)]
#[derive(Debug, Deref, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature(pub Array<u8, { SIGNATURE_LENGTH }>);
