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
//

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;

pub fn pairings_is_equal(a: G1Affine, b: G2Affine, c: G1Affine, d: G2Affine) -> bool {
    let p1 = Bn254::pairing(a, b);
    let p2 = Bn254::pairing(c, d);
    p1 == p2
}
