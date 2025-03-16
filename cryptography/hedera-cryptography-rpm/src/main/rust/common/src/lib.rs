// TODO: better error types
#![allow(clippy::result_unit_err)]

use alloy_sol_types::sol;

pub mod address_book;
pub mod ed25519;
pub mod sha256;
pub mod statement;
pub mod errors;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    #[derive(Debug)]
    struct PublicValuesStruct {
        bytes32 ab_genesis_hash;
        bytes32 ab_curr_hash;
        bytes32 ab_next_hash;
        bytes32 tss_vk_hash;
        bytes32 vk_digest;
    }
}
