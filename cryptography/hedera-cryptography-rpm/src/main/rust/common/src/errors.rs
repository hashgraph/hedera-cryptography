//
// Copyright (C) 2024 Hedera Hashgraph, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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