use raps::raps::RAPS as RAPS;
use sp1_sdk::{SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey};
use std::io::{self, Read, Write};
use byteorder::{BigEndian, ReadBytesExt};

// this method is used to read a byte array from a reader
// it first reads a 4-byte length prefix, which is in big endian
// the length prefix indicates how many bytes to read next
fn read_byte_array<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    // Read the length prefix (4 bytes, big endian)
    let len = reader.read_u32::<BigEndian>()?;
    // Read `len` bytes
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    // let us grab the inputs first from stdin
    // we expect the ordering to be compression_pk, raps_vk, proof
    let compression_pk = read_byte_array(&mut handle)?;
    let raps_vk = read_byte_array(&mut handle)?;
    let proof = read_byte_array(&mut handle)?;

    let compression_pk: SP1ProvingKey = bincode::deserialize(compression_pk.as_ref()).expect("failed to deserialize pk");
    let raps_vk: SP1VerifyingKey = bincode::deserialize(raps_vk.as_ref()).expect("failed to deserialize vk");
    let proof: SP1ProofWithPublicValues = bincode::deserialize(proof.as_ref()).expect("failed to deserialize prev_proof");

    // the main compression logic
    let compressed_proof = RAPS::compress_rotation_proof(
        &compression_pk,
        &raps_vk,
        proof,
    ).expect("failed to compress proof");

    // serialize the compressed proof to a byte array
    let mut compressed_proof_buf: Vec<u8> = Vec::new();
    bincode::serialize_into(&mut compressed_proof_buf, &compressed_proof).expect("failed to serialize proof");

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    handle.write_all(&compressed_proof_buf)?; // Writes the bytes
    handle.flush()?;          // Ensures the data is written immediately

    Ok(())
}