use sp1_sdk::{
    SP1ProofWithPublicValues,
    SP1ProvingKey,
    SP1VerifyingKey,
    ProverClient,
    SP1Stdin,
    HashableKey
};
use std::io::{self, Read, Write};
use byteorder::{BigEndian, ReadBytesExt};
use alloy_sol_types::SolType;
use ab_rotation_lib::{statement::CompressedStatement, PublicValuesStruct, errors::*};

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

fn write_byte_array<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    // let us first write the length of the compressed proof
    let len_bytes = (data.len() as u32).to_be_bytes();
    writer.write_all(&len_bytes)?;

    writer.write_all(&data)?; // Writes the bytes
    writer.flush()?;          // Ensures the data is written immediately

    Ok(())
}

fn compress_rotation_proof(
    compression_pk: &SP1ProvingKey,               // proving key output by sp1 setup for compression zkVM
    raps_vk: &SP1VerifyingKey,                    // verifying key output by sp1 setup for RAPS zkVM
    proof: SP1ProofWithPublicValues,              // the proof to compress
) -> Result<SP1ProofWithPublicValues, RAPSError>{
    let prover = ProverClient::builder().cpu().build();

    let parsed_proof = PublicValuesStruct::abi_decode(&proof.public_values.to_vec(), true)
        .map_err(|_| RAPSError::InvalidInput(("error decoding previous proof").to_string()))?;

    let statement = CompressedStatement {
        vk_digest: raps_vk.hash_u32(),
        ab_genesis_hash: parsed_proof.ab_genesis_hash.0,
        ab_current_hash: parsed_proof.ab_curr_hash.0,
        ab_next_hash: parsed_proof.ab_next_hash.0,
        tss_vk_current_hash: parsed_proof.tss_vk_hash.0,
    };

    // Supply the statement and (optional) prev proof to the zkVM
    let mut stdin = SP1Stdin::new();
    stdin.write(&statement);

    let box_proof_inner = proof
        .proof
        .try_as_compressed()
        .ok_or(RAPSError::InvalidInput("expected valid proof to compress".to_string()))?;

    stdin.write_proof(*box_proof_inner, raps_vk.vk.clone());

    // Generate the proofs
    let compressed_proof: SP1ProofWithPublicValues = prover
        .prove(compression_pk, &stdin)
        .groth16()
        .run()
        .map_err(|_| RAPSError::ProverError)?;

    Ok(compressed_proof)
}

fn main() -> io::Result<()> {
    let mut stdin_handle = io::stdin().lock();

    // let us grab the inputs first from stdin
    // we expect the ordering to be compression_pk, raps_vk, proof
    let compression_pk = read_byte_array(&mut stdin_handle)?;
    let raps_vk = read_byte_array(&mut stdin_handle)?;
    let proof = read_byte_array(&mut stdin_handle)?;

    let compression_pk: SP1ProvingKey = bincode::deserialize(compression_pk.as_ref()).expect("failed to deserialize pk");
    let raps_vk: SP1VerifyingKey = bincode::deserialize(raps_vk.as_ref()).expect("failed to deserialize vk");
    let proof: SP1ProofWithPublicValues = bincode::deserialize(proof.as_ref()).expect("failed to deserialize prev_proof");

    // the main compression logic
    let compressed_proof = compress_rotation_proof(
        &compression_pk,
        &raps_vk,
        proof,
    ).expect("failed to compress proof");

    // serialize the compressed proof to a byte array
    let mut compressed_proof_buf: Vec<u8> = Vec::new();
    bincode::serialize_into(&mut compressed_proof_buf, &compressed_proof).expect("failed to serialize proof");

    let mut stdout_handle = io::stdout().lock();

    // sp1 emits debugging output to stdout prior to our own output,
    // so we emit this marker to indicate that our output follows:
    stdout_handle.write(b"<TSS OUTPUT BEGIN>");
    stdout_handle.flush();

    write_byte_array(&mut stdout_handle, &compressed_proof_buf)?;

    Ok(())
}