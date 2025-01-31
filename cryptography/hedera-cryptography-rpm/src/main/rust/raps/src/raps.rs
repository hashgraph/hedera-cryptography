use ab_rotation_lib::{
    address_book::{AddressBook, Signatures},
    ed25519::{Signature, SigningKey, VerifyingKey, ENTROPY_SIZE},
    statement::Statement,
    PublicValuesStruct,
};
use alloy_sol_types::SolType;
use sp1_sdk::{
    HashableKey, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};

pub struct RAPS {}

impl RAPS {
    pub fn keygen(seed: [u8; ENTROPY_SIZE]) -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(seed);
        let vk = VerifyingKey(sk.0.verifying_key());
        (sk, vk)
    }

    pub fn sign(sk: &SigningKey, message: &[u8]) -> Signature {
        sk.sign(message)
    }

    pub fn verify_signature(vk: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        vk.verify(message, signature)
    }

    pub fn rotation_message(ab_next: &AddressBook, tss_vk_hash: [u8; 32]) -> Vec<u8> {
        let ab_next_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_next);

        let message = [ab_next_hash.as_slice(), tss_vk_hash.as_slice()]
            .into_iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        message
    }

    pub fn proof_setup(zkvm_elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        // Setup the prover client.
        let client = ProverClient::from_env();

        // Setup the program.
        let (pk, vk) = client.setup(zkvm_elf);

        (pk, vk)
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates the first proof for the genesis AddressBook.
    pub fn construct_rotation_proof(
        pk: &SP1ProvingKey,                           // proving key output by sp1 setup
        vk: &SP1VerifyingKey,                         // verifying key output by sp1 setup
        ab_genesis_hash: &[u8; 32],                   // genesis AddressBook hash
        ab_curr: &AddressBook,                        // current AddressBook
        ab_next: &AddressBook,                        // next AddressBook
        prev_proof: Option<SP1ProofWithPublicValues>, // the previous proof
        tss_vk_hash: &[u8; 32], // TSS verification key for the next AddressBook
        signatures: &Signatures, // signatures attesting the next AddressBook
    ) -> SP1ProofWithPublicValues {
        // Setup the prover client.
        let client = ProverClient::from_env();

        let (ab_curr_hash, _ab_next_hash, stmt) = generate_statement(
            *ab_genesis_hash,
            prev_proof.as_ref(),
            vk.hash_u32(),
            ab_curr,
            ab_next,
            signatures,
            *tss_vk_hash,
        );

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();
        stdin.write(&stmt);
        if ab_curr_hash != *ab_genesis_hash {
            stdin.write_proof(
                *prev_proof
                    .expect("expected previous proof")
                    .proof
                    .try_as_compressed()
                    .unwrap(),
                vk.vk.clone(),
            );
        }

        // Generate the proofs
        let proof: SP1ProofWithPublicValues = client
            .prove(pk, &stdin)
            .compressed()
            .run()
            .expect("failed to generate proof");

        proof
    }

    pub fn verify_proof(vk: &SP1VerifyingKey, proof: &SP1ProofWithPublicValues) -> bool {
        // Setup the prover client.
        let client = ProverClient::from_env();
        let verification = client.verify(proof, vk);
        verification.is_ok()
    }
}

fn generate_statement(
    ab_genesis_hash: [u8; 32],
    prev_proof: Option<&SP1ProofWithPublicValues>,
    vk_digest: [u32; 8],
    ab_curr: &AddressBook,
    ab_next: &AddressBook,
    signatures: &Signatures,
    tss_vk_next_hash: [u8; 32],
) -> ([u8; 32], [u8; 32], Statement) {
    let ab_curr_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_curr);
    let ab_next_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_next);

    let ab_prev_hash = prev_proof.map(|prev_proof| {
        let parsed_prev_proof =
            PublicValuesStruct::abi_decode(&prev_proof.public_values.to_vec(), true).unwrap();
        parsed_prev_proof.ab_curr_hash.0
    });

    let tss_vk_prev_hash = prev_proof.map(|prev_proof| {
        let parsed_prev_proof =
            PublicValuesStruct::abi_decode(&prev_proof.public_values.to_vec(), true).unwrap();
        parsed_prev_proof.tss_vk_hash.0
    });

    let statement = Statement {
        vk_digest,
        ab_genesis_hash,
        ab_prev_hash,
        ab_curr: ab_curr.clone(),
        ab_next_hash,
        tss_vk_prev_hash,
        tss_vk_next_hash,
        signatures: signatures.clone(),
    };

    (ab_curr_hash, ab_next_hash, statement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::ToSmallVec;
    use sp1_sdk::include_elf;

    /// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
    pub const AB_ROTATION_ELF: &[u8] = include_elf!("ab-rotation-program");

    #[test]
    fn run_simulation() {
        // Setup the logger.
        sp1_sdk::utils::setup_logger();

        // Setup the program.
        let (pk, vk) = RAPS::proof_setup(AB_ROTATION_ELF);

        // AB 0 (genesis AB)
        let (genesis_signing_keys, genesis_verifying_keys) = generate_signers::<5>();
        let ab_genesis = AddressBook::new(genesis_verifying_keys.to_vec(), [1; 5].to_vec());

        let genesis_signatures = subset_sign(
            &genesis_signing_keys,
            &[true; 5],
            &RAPS::rotation_message(&ab_genesis, [0u8; 32]),
        );

        let ab_genesis_hash =
            ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_genesis);
        let genesis_proof = RAPS::construct_rotation_proof(
            &pk,
            &vk,
            &ab_genesis_hash,
            &ab_genesis,
            &ab_genesis,
            None,
            &[0u8; 32],
            &Signatures(genesis_signatures.to_smallvec()),
        );

        let mut prev_ab = ab_genesis;
        let mut prev_proof = genesis_proof;
        let mut prev_signing_keys = genesis_signing_keys;
        let mut prev_verifying_keys = genesis_verifying_keys;

        // simulate 15 rotations
        for day in 0..15 {
            assert!(RAPS::verify_proof(&vk, &prev_proof));
            debug(&prev_proof);

            let (next_signing_keys, next_verifying_keys) = if day % 2 == 0 {
                // half of the days, we dont rotate
                generate_signers::<5>()
            } else {
                (prev_signing_keys.clone(), prev_verifying_keys.clone())
            };

            let next_ab = AddressBook::new(next_verifying_keys.to_vec(), [1; 5].to_vec());

            let signatures = subset_sign(
                &prev_signing_keys,
                &[true; 5],
                &RAPS::rotation_message(&next_ab, [0u8; 32]),
            );

            let next_proof = RAPS::construct_rotation_proof(
                &pk,
                &vk,
                &ab_genesis_hash,
                &prev_ab,
                &next_ab,
                Some(prev_proof),
                &[0u8; 32],
                &Signatures(signatures.to_smallvec()),
            );

            prev_proof = next_proof;
            prev_ab = next_ab;
            prev_signing_keys = next_signing_keys;
            prev_verifying_keys = next_verifying_keys;
        }
    }

    fn generate_signers<const N: usize>() -> ([SigningKey; N], [VerifyingKey; N]) {
        let keys: [(SigningKey, VerifyingKey); N] =
            std::array::from_fn(|i| RAPS::keygen([i as u8; ENTROPY_SIZE]));
        let signing_keys: [SigningKey; N] = keys.clone().map(|sk| sk.0);
        let verifying_keys: [VerifyingKey; N] = keys.map(|sk| sk.1);

        (signing_keys, verifying_keys)
    }

    fn subset_sign<const N: usize>(
        signing_keys: &[SigningKey; N],
        signers: &[bool; N],
        message: &[u8],
    ) -> [Option<Signature>; N] {
        core::array::from_fn(|i| signers[i].then_some(signing_keys[i].sign(message)))
    }

    fn debug(proof: &SP1ProofWithPublicValues) {
        let parsed_proof =
            PublicValuesStruct::abi_decode(&proof.public_values.to_vec(), true).unwrap();
        println!("------------ BEGIN Roster Attestation Proof ------------");
        println!(
            "ab_genesis_hash: 0x{}",
            &hex::encode(parsed_proof.ab_genesis_hash)[..8]
        );
        println!(
            "ab_curr_hash:    0x{}",
            &hex::encode(parsed_proof.ab_curr_hash)[..8]
        );
        println!(
            "ab_next_hash:    0x{}",
            &hex::encode(parsed_proof.ab_next_hash)[..8]
        );
        println!(
            "tss_vk:          0x{}",
            &hex::encode(parsed_proof.tss_vk_hash)[..8]
        );
        println!("------------ END Roster Attestation Proof ------------");
    }
}
