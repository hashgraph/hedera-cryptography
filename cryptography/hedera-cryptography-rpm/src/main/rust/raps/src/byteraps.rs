use alloy_sol_types::SolType;
use crate::raps::RAPS;
use smallvec::SmallVec;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey};

use ab_rotation_lib::address_book::Signatures;

pub use ab_rotation_lib::address_book::AddressBook;
pub use ab_rotation_lib::ed25519::{Signature, SigningKey, VerifyingKey, ENTROPY_SIZE};
pub use ab_rotation_lib::PublicValuesStruct;

pub struct ByteRAPS {}

/// presents a byte array interface to the RAPS library
impl ByteRAPS {

    /// outputs the byte array for the signing key,
    /// followed by the byte array for the verifying key
    pub fn keygen(seed: [u8; ENTROPY_SIZE]) -> (Vec<u8>, Vec<u8>) {
        let (sk, vk) = RAPS::keygen(seed);
        (sk.to_bytes().to_vec(), vk.to_bytes().to_vec())
    }

    pub fn sign(sk: impl AsRef<[u8]>, message: impl AsRef<[u8]>) -> Vec<u8> {
        let sk = SigningKey::from_bytes(sk.as_ref().try_into().unwrap());
        sk.sign(message.as_ref()).0.to_vec()
    }

    pub fn compute_address_book_hash(verifying_keys: Vec<impl AsRef<[u8]>>, weights: Vec<u64>) -> [u8; 32] {
        let ab = build_address_book(verifying_keys, weights);
        ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab)
    }

    pub fn compute_tss_vk_hash(tss_vk: impl AsRef<[u8]>) -> [u8; 32] {
        ab_rotation_lib::address_book::digest_sha256(tss_vk)
    }

    pub fn rotation_message(ab_hash: &[u8; 32], tss_vk_hash: &[u8; 32]) -> Vec<u8> {
        let message = [ab_hash.as_slice(), tss_vk_hash.as_slice()]
            .into_iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        message
    }

    pub fn proof_setup(zkvm_elf: impl AsRef<[u8]>) -> (Vec<u8>, Vec<u8>) {
        // Setup the prover client.
        let client = ProverClient::from_env();

        // Setup the program.
        let (pk, vk) = client.setup(zkvm_elf.as_ref());

        let mut pk_buf: Vec<u8> = Vec::new();
        bincode::serialize_into(&mut pk_buf, &pk).expect("failed to serialize pk");

        let mut vk_buf: Vec<u8> = Vec::new();
        bincode::serialize_into(&mut vk_buf, &vk).expect("failed to serialize vk");

        (pk_buf, vk_buf)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn construct_rotation_proof(
        pk: impl AsRef<[u8]>,                       // proving key output by sp1 setup
        vk: impl AsRef<[u8]>,                       // verifying key output by sp1 setup
        ab_genesis_hash: &[u8; 32],                 // genesis AddressBook hash
        ab_curr: (Vec<impl AsRef<[u8]>>, Vec<u64>), // current AddressBook
        ab_next: (Vec<impl AsRef<[u8]>>, Vec<u64>), // next AddressBook
        prev_proof: Option<impl AsRef<[u8]>>,       // the previous proof
        tss_vk_hash: &[u8; 32],                     // TSS verification key for the next AddressBook
        signatures: Vec<Option<impl AsRef<[u8]>>>,  // signatures attesting the next AddressBook
    ) -> Vec<u8> {
        let pk: SP1ProvingKey = bincode::deserialize(pk.as_ref()).expect("failed to deserialize pk");
        let vk: SP1VerifyingKey = bincode::deserialize(vk.as_ref()).expect("failed to deserialize vk");

        let ab_curr = build_address_book(ab_curr.0, ab_curr.1);
        let ab_next = build_address_book(ab_next.0, ab_next.1);

        let prev_proof: Option<SP1ProofWithPublicValues> = prev_proof
            .map(|p| bincode::deserialize(p.as_ref()).expect("failed to deserialize prev_proof"));

        let signatures = Signatures(SmallVec::from_vec(
            signatures
                .into_iter()
                .map(|s| s.map(|s| Signature(serde_big_array::Array(s.as_ref().try_into().unwrap()))))
                .collect(),
        ));

        let proof = RAPS::construct_rotation_proof(
            &pk,
            &vk,
            ab_genesis_hash,
            &ab_curr,
            &ab_next,
            prev_proof,
            tss_vk_hash,
            &signatures,
        );

        let mut proof_buf: Vec<u8> = Vec::new();
        bincode::serialize_into(&mut proof_buf, &proof).expect("failed to serialize proof");

        proof_buf
    }

    pub fn verify_proof(vk: impl AsRef<[u8]>, proof: impl AsRef<[u8]>) -> bool {
        let vk: SP1VerifyingKey = bincode::deserialize(vk.as_ref()).expect("failed to deserialize vk");
        let proof: SP1ProofWithPublicValues =
            bincode::deserialize(proof.as_ref()).expect("failed to deserialize proof");
        RAPS::verify_proof(&vk, &proof)
    }

    pub fn tss_vk_hash_from_proof(proof: impl AsRef<[u8]>) -> [u8; 32] {
        let proof: SP1ProofWithPublicValues =
            bincode::deserialize(proof.as_ref()).expect("failed to deserialize proof");
        let bytes = proof.public_values.as_slice();
        let pv = PublicValuesStruct::abi_decode(bytes, true).unwrap();
        pv.tss_vk_hash.0
    }

}

fn build_address_book(verifying_keys: Vec<impl AsRef<[u8]>>, weights: Vec<u64>) -> AddressBook {
    let verifying_keys: Vec<VerifyingKey> = verifying_keys
        .into_iter()
        .map(|vk| VerifyingKey(vk.as_ref().try_into().unwrap()))
        .collect::<Vec<_>>();
    AddressBook::new(verifying_keys, weights)
}

#[cfg(test)]
mod tests {
    /// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
    pub const AB_ROTATION_ELF: &[u8] = sp1_sdk::include_elf!("ab-rotation-program");

    #[derive(Debug, Clone)]
    pub struct Roster {
        pub verifying_keys: Vec<Vec<u8>>,
        pub signing_keys: Vec<Vec<u8>>,
        pub weights: Vec<u64>,
    }

    impl Roster {
        pub fn new(n: usize) -> Self {
            let mut verifying_keys = Vec::new();
            let mut signing_keys = Vec::new();
            let weights = vec![1u64; n];

            for _ in 0..n {
                let (sk, vk) = super::ByteRAPS::keygen([i as u8; ENTROPY_SIZE]);
                signing_keys.push(sk);
                verifying_keys.push(vk);
            }

            Roster {
                verifying_keys,
                signing_keys,
                weights,
            }
        }

        pub fn subset_sign(&self, signers: &[bool], message: &[u8]) -> Vec<Option<Vec<u8>>> {
            let mut signatures = Vec::new();
            for (i, &active) in signers.iter().enumerate() {
                if active {
                    signatures.push(Some(super::ByteRAPS::sign(&self.signing_keys[i], message,)));
                } else {
                    signatures.push(None);
                }
            }
            signatures
        }
    }

    #[test]
    fn run_simulation() {
        // Setup the logger.
        sp1_sdk::utils::setup_logger();

        let tss_vk_hash = [0u8; 32];

        // Setup the program.
        let (pk, vk) = super::ByteRAPS::proof_setup(AB_ROTATION_ELF);

        // AB 0 (genesis AB)
        let genesis_committee = Roster::new(5);
        let genesis_ab_hash = super::ByteRAPS::compute_address_book_hash(
            genesis_committee.verifying_keys.clone(),
            genesis_committee.weights.clone(),
        );

        let genesis_proof = super::ByteRAPS::construct_rotation_proof(
            &pk,
            &vk,
            &genesis_ab_hash,
            (
                genesis_committee.verifying_keys.clone(),
                genesis_committee.weights.clone(),
            ),
            (
                genesis_committee.verifying_keys.clone(),
                genesis_committee.weights.clone(),
            ),
            None as Option<Vec<u8>>,
            &[0u8; 32],
            genesis_committee.subset_sign(
                &[true; 5],
                &super::ByteRAPS::rotation_message(&genesis_ab_hash, &tss_vk_hash),
            ),
        );

        let mut prev_proof = genesis_proof;
        let mut prev_roster = genesis_committee;

        // simulate a few rotations
        for day in 0..5 {
            assert!(super::ByteRAPS::verify_proof(&vk, &prev_proof));

            let next_roster = if day % 2 == 0 {
                Roster::new(5)
            } else {
                prev_roster.clone()
            };
            let next_roster_hash = super::ByteRAPS::compute_address_book_hash(
                next_roster.verifying_keys.clone(),
                next_roster.weights.clone(),
            );

            let next_proof = super::ByteRAPS::construct_rotation_proof(
                &pk,
                &vk,
                &genesis_ab_hash,
                (
                    prev_roster.verifying_keys.clone(),
                    prev_roster.weights.clone(),
                ),
                (
                    next_roster.verifying_keys.clone(),
                    next_roster.weights.clone(),
                ),
                Some(prev_proof),
                &[0u8; 32],
                prev_roster.subset_sign(
                    &[true; 5],
                    &super::ByteRAPS::rotation_message(&next_roster_hash, &tss_vk_hash),
                ),
            );

            prev_proof = next_proof;
            prev_roster = next_roster;
        }
    }
}
