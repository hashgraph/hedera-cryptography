// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use ark_ec::hashing::HashToCurveError;
use ark_serialize::SerializationError;

/// Error enum to wrap underlying failures in HinTS operations, 
/// or wrap errors coming from dependencies (namely, arkworks).
#[derive(Debug)]
pub enum HinTSError {
    /// Error coming from `ark_serialize` upon deserialization
    EncodingError(SerializationError),
    /// Error coming from `ark_ec` upon hashing to curve
    HashingError(HashToCurveError),
    /// Happens when the network size parameter is not a power of 2
    InvalidNetworkSize(usize),
    /// Happens when the CRS is insufficient for the operation
    InsufficientCRS(usize),
    /// Multi-purpose error type for describing invalid inputs
    InvalidInput(String),
    /// Multi-purpose error type for when the cryptography failed
    CryptographyCatastrophe(String),
}

impl Error for HinTSError {}

impl fmt::Display for HinTSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HinTSError::EncodingError(ref err) => err.fmt(f),
            HinTSError::InvalidNetworkSize(n) => write!(f, "Network size must be a power of 2. Got {n}"),
            HinTSError::InsufficientCRS(d) => write!(f, "CRS is insufficient for the operation. Expected degree {d}"),
            HinTSError::InvalidInput(ref s) => write!(f, "Invalid input: {s}"),
            HinTSError::CryptographyCatastrophe(ref s) => write!(f, "Cryptography catastrophe: {s}"),
            HinTSError::HashingError(ref err) => err.fmt(f),
        }
    }
}

impl From<SerializationError> for HinTSError {
    fn from(err: SerializationError) -> HinTSError {
        HinTSError::EncodingError(err)
    }
}

impl From<HashToCurveError> for HinTSError {
    fn from(err: HashToCurveError) -> HinTSError {
        HinTSError::HashingError(err)
    }
}
