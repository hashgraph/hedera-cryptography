// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;

/// Error enum to wrap underlying failures in RAPS operations, 
/// or wrap errors coming from dependencies (namely, arkworks).
#[derive(Debug)]
pub enum RAPSError {
    /// Error coming from `bincode` serialization
    EncodingError(bincode::Error),
    /// Multi-purpose error type for describing invalid inputs
    InvalidInput(String),
    /// Multi-purpose error type for describing prover failure
    ProverError,
}

impl Error for RAPSError {}

impl fmt::Display for RAPSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RAPSError::EncodingError(ref err) => err.fmt(f),
            RAPSError::InvalidInput(ref s) => write!(f, "Invalid input: {s}"),
            RAPSError::ProverError => write!(f, "Prover error"),
        }
    }
}

impl From<bincode::Error> for RAPSError {
    fn from(err: bincode::Error) -> RAPSError {
        RAPSError::EncodingError(err)
    }
}
