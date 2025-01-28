use crate::{address_book::AddressBook, address_book::Signatures};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Statement {
    pub vk_digest: [u32; 8],
    pub ab_genesis_hash: [u8; 32],
    pub ab_prev_hash: Option<[u8; 32]>,
    pub ab_curr: AddressBook,
    pub ab_next_hash: [u8; 32],
    pub tss_vk_prev_hash: Option<[u8; 32]>,
    pub tss_vk_next_hash: [u8; 32],
    pub signatures: Signatures,
}
