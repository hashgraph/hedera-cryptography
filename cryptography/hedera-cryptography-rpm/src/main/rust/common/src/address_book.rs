use derive_more::derive::Deref;
use serde::{Deserialize, Serialize};
use serde_big_array::Array;
use smallvec::SmallVec;

use crate::ed25519;
use crate::sha256;

pub type Weight = u64;

pub const MAXIMUM_VALIDATORS: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AddressBookEntry {
    pub ed25519_public_key: Array<u8, { ed25519::PUBLIC_KEY_LENGTH }>,
    pub weight: Weight,
}

#[repr(transparent)]
#[derive(Debug, Deref, Clone, Serialize, Deserialize)]
pub struct AddressBook(pub SmallVec<[AddressBookEntry; MAXIMUM_VALIDATORS]>);

impl AddressBook {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&AddressBookEntry> {
        self.0.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AddressBookEntry> {
        self.0.iter()
    }

    pub fn new(verifying_keys: Vec<ed25519::VerifyingKey>, weights: Vec<u64>) -> Self {
        assert!(
            verifying_keys.len() <= MAXIMUM_VALIDATORS,
            "Too many verifying keys"
        );
        assert!(
            verifying_keys.len() == weights.len(),
            "Different number of verifying keys and weights"
        );
        let entries: Vec<AddressBookEntry> = verifying_keys
            .iter()
            .zip(weights.iter())
            .map(|(vk, w)| AddressBookEntry {
                ed25519_public_key: Array(vk.to_bytes()),
                weight: *w,
            })
            .collect();
        AddressBook(SmallVec::from_vec(entries.to_vec()))
    }
}

#[repr(transparent)]
#[derive(Debug, Deref, Clone, Serialize, Deserialize)]
pub struct Signatures(pub SmallVec<[Option<ed25519::Signature>; MAXIMUM_VALIDATORS]>);

/// Calculates the total weight of the validators in the current AB
pub fn calculate_total_weight(ab: &AddressBook) -> u64 {
    ab.iter().map(|abe| abe.weight).sum()
}

/// Calculates the cumulative weight of the validators in the current AB
/// that have signed the next AB's hash
pub fn calculate_signers_weight(ab: &AddressBook, signatures: &Signatures, message: &[u8]) -> u64 {
    // NOTE: assumes that signatures are presented in the same order
    //       as the validators in the current AB
    core::iter::zip(ab.0.iter(), signatures.0.iter()).fold(0, |acc, (abe, ms)| -> u64 {
        let added_weight = ms
            .as_ref()
            .map(|signature_bytes| {
                let verifying_key =
                    <ed25519_dalek::VerifyingKey>::from_bytes(&abe.ed25519_public_key)
                        .expect("A valid ED25519 public key");
                let signature = <ed25519_dalek::Signature>::from_bytes(signature_bytes);
                verifying_key
                    .verify_strict(message, &signature)
                    .map(|_| abe.weight)
                    .expect("Invalid signature")
            })
            .unwrap_or(0);

        acc + added_weight
    })
}

pub fn serialize_and_digest_sha256(data: &impl serde::Serialize) -> [u8; 32] {
    // NOTE: uses the same `bincode` as the `sp1_zkvm::io::read` and family
    let data_bytes = bincode::serialize(data).unwrap();
    sha256::digest_sha256(data_bytes)
}
