#
# Copyright (C) 2024 Hedera Hashgraph, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

p =21888242871839275222246405745257275088696311157297823662689037894645226208583
Fp = GF(p)

Fp2.<u> = GF(p^2, modulus=x^2+1)

E1 = EllipticCurve(Fp,[0,3])
E2 = EllipticCurve(Fp2, [0, 3/(9+u)])

r = E1.order()

G1 = E1(1, 2)

x_g2 = Fp2(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed + 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2*u)
y_g2 = Fp2(0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa + 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b*u)

G2 = E2(x_g2, y_g2)

assert (r*G2).is_zero(), "G2 does not have the correct order"

def random_scalar():
    return randint(1, r-1)

def point_to_json(P):
    if P.is_zero():
        return {"x": "0", "y": "0"}
    x, y = P.xy()
    if P.curve() == E1:
        return {"x": str(x), "y": str(y)}
    else:  # E2
        return {
            "x": {"c0": str(x[0]), "c1": str(x[1])},
            "y": {"c0": str(y[0]), "c1": str(y[1])}
        }

def generate_info():
    scalar = random_scalar()
    g1point = scalar * G1
    g2point = scalar * G2
    return scalar, g1point, g2point

def generate_non_r_torsion_point():
    while True:
        P = E2.random_point()
        if (p + 1 - E2.trace_of_frobenius()) * P != E2(0) and r * P != E2(0):
            return P
