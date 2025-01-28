// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ab_rotation_lib::{
    address_book::{
        calculate_signers_weight, calculate_total_weight, digest_sha256,
        serialize_and_digest_sha256,
    },
    statement::Statement,
    PublicValuesStruct,
};
use alloy_sol_types::SolValue;

pub fn main() {
    // Get the passed statement
    println!("cycle-tracker-start: parsing statement_in");
    let statement = sp1_zkvm::io::read::<Statement>();
    println!("cycle-tracker-end: parsing statement_in");

    assert!(
        statement.signatures.len() == statement.ab_curr.len(),
        "There has to be an (optional) signature for each current validator, got {} and {}, respectively, full {:?}",
        statement.signatures.len(),
        statement.ab_curr.len(),
        statement,
    );

    // Get the SHA256 of the genesis AB
    let ab_genesis_hash: [u8; 32] = statement.ab_genesis_hash;

    // Get the SHA256 of the current AB (using the provided ECALL)
    println!("cycle-tracker-start: digesting current ab");
    let ab_curr_hash: [u8; 32] = serialize_and_digest_sha256(&statement.ab_curr);
    println!("cycle-tracker-end: digesting current ab");

    // Get the SHA256 of the next AB
    let ab_next_hash: [u8; 32] = statement.ab_next_hash;

    // If the current AB is different from the genesis one
    // try to verify a recursive proof for the current AB
    if ab_curr_hash != ab_genesis_hash {
        println!("cycle-tracker-start: proving recursive proof");
        // Get the SHA256 of the prev AB, asserting it exists (since we need it)
        let ab_prev_hash: [u8; 32] = statement
            .ab_prev_hash
            .expect("ab_prev_hash needed proving the recursive SP1 proof");

        let tss_vk_prev_hash = statement
            .tss_vk_prev_hash
            .expect("tss_vk_prev needed proving the recursive SP1 proof");

        let prev_pv = PublicValuesStruct {
            ab_genesis_hash: ab_genesis_hash.into(),
            ab_curr_hash: ab_prev_hash.into(),
            ab_next_hash: ab_curr_hash.into(),
            tss_vk_hash: tss_vk_prev_hash.into(),
        };

        let prev_pv_abi_encoded = prev_pv.abi_encode();
        let pv_digest = digest_sha256(&prev_pv_abi_encoded);
        sp1_zkvm::lib::verify::verify_sp1_proof(&statement.vk_digest, &pv_digest);
        println!("cycle-tracker-end: proving recursive proof");
    }

    println!("cycle-tracker-start: calculating total weight");
    let total_weight = calculate_total_weight(&statement.ab_curr);
    println!("cycle-tracker-end: calculating total weight");

    let message = [
        statement.ab_next_hash.as_slice(),
        statement.tss_vk_next_hash.as_slice(),
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect::<Vec<_>>();

    println!("cycle-tracker-start: calculating signers weight");
    let signers_weight =
        calculate_signers_weight(&statement.ab_curr, &statement.signatures, &message);
    println!("cycle-tracker-end: calculating signers weight");

    // Assert that enough (1/3-rd) of the current validators have signed the next AB
    // NOTE: not using floats to avoid rounding issues
    let enough_signatures = 3 * signers_weight >= total_weight;
    assert!(
        enough_signatures,
        "Have enough signatures, need a third, got {}",
        (signers_weight as f64 / total_weight as f64)
    );

    #[allow(clippy::diverging_sub_expression, unused)]
    let public_values = PublicValuesStruct {
        ab_genesis_hash: ab_genesis_hash.into(),
        ab_curr_hash: ab_curr_hash.into(),
        ab_next_hash: ab_next_hash.into(),
        tss_vk_hash: statement.tss_vk_next_hash.into(),
    };

    sp1_zkvm::io::commit_slice(&public_values.abi_encode());
}
