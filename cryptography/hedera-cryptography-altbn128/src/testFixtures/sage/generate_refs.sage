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

from sagelib.utils import *
from sagelib.svdw import generic_svdw
import json

# Generate random points
num_points = 1000
points = {
    "GROUP1": [],
    "GROUP2": [],
    "E2_non_G2": [],
    "SCALARS": [],
    "svdw": []
}

for _ in range(num_points):
    # Generate keypair and signature
    scalars, g1points, g2points = generate_info()
    points["SCALARS"].append(str(scalars))
    points["GROUP1"].append(point_to_json(g1points) )
    points["GROUP2"].append(point_to_json(g2points))

    # E2 point not in G2
    P_non_G2 = generate_non_r_torsion_point()
    points["E2_non_G2"].append(point_to_json(P_non_G2))
 

###
# now we generate the SVDW vectors for the comparison with the solidity implementation

svdw = generic_svdw(E1)
for _ in range(num_points):
    u = Fp.random_element()
    if u not in svdw.undefs:
        x, y = svdw.map_to_point(u)
        assert E1(x,y), f"point ({x},{y}) is not on the curve for u = {u}"
        points["svdw"].append({
            "i" : str(u),
            **point_to_json(E1(x,y))})

pointsTwo = {'SCALARS': points['SCALARS']}
for field in list(points.keys()):
	simplifiedField = []
	print(field)
	if field == 'SCALARS':
		continue
	elif field == 'GROUP1' or field == 'svdw':
		for entry in points[field]:
			simplifiedField.append([str(value) for value in list(entry.values())])
	else:
		for entry in points[field]:
			objPair = []
			for obj in list(entry.values()):
				for value in list(obj.values()):
					objPair.append(str(value))
			simplifiedField.append(objPair)
	pointsTwo[field] = simplifiedField
with open('altbn128_ext_data.json', 'w') as f:
	f.write(json.dumps(pointsTwo,indent=2))
