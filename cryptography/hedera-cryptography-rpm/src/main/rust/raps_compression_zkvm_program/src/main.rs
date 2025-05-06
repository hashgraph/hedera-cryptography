// SPDX-License-Identifier: Apache-2.0

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ab_rotation_lib::{
    address_book::serialize_and_digest_sha256,
    sha256::digest_sha256,
    statement::CompressedStatement,
    PublicValuesStruct, CompressedPublicValuesStruct,
};
use alloy_sol_types::SolValue;

pub fn main() {
    // Get the passed statement
    println!("cycle-tracker-start: parsing statement_in");
    let statement = sp1_zkvm::io::read::<CompressedStatement>();
    println!("cycle-tracker-end: parsing statement_in");

    let ab_genesis_hash: [u8; 32] = statement.ab_genesis_hash;
    let ab_current_hash: [u8; 32] = statement.ab_current_hash;
    let ab_next_hash: [u8; 32] = statement.ab_next_hash;
    let tss_vk_current_hash: [u8; 32] = statement.tss_vk_current_hash;

    // we need to flatten the vk_digest from an array of u32 to a byte array
    let mut vk_digest = [0u8; 32];
    for (i, &num) in statement.vk_digest.iter().enumerate() {
        vk_digest[i * 4..(i + 1) * 4].copy_from_slice(&num.to_le_bytes());
    }

    let pv = PublicValuesStruct {
        ab_genesis_hash: ab_genesis_hash.into(),
        ab_curr_hash: ab_current_hash.into(),
        ab_next_hash: ab_next_hash.into(),
        tss_vk_hash: tss_vk_current_hash.into(),
        vk_digest: vk_digest.into(),
    };

    let compressed_pv = CompressedPublicValuesStruct {
        ab_genesis_hash: ab_genesis_hash.into(),
        ab_hash: ab_next_hash.into(),
        tss_vk_hash: tss_vk_current_hash.into(),
        vk_digest: vk_digest.into(),
    };

    let pv_abi_encoded = pv.abi_encode();
    let pv_digest = digest_sha256(&pv_abi_encoded);
    sp1_zkvm::lib::verify::verify_sp1_proof(&statement.vk_digest, &pv_digest);

    sp1_zkvm::io::commit_slice(&compressed_pv.abi_encode());
}
