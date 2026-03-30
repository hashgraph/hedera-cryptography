#!/usr/bin/env bash
set -euo pipefail

# Runs a sample WRAPS ceremony with:
# - phase 1 updates: 2
# - phase 2 updates: 2
#
# Usage:
#   ceremony/run_sample_ceremony.sh <root-folder>
#
# Example:
#   ceremony/run_sample_ceremony.sh /tmp/tss

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <root-folder>"
  exit 1
fi

RUN_ROOT="$1"
mkdir -p "${RUN_ROOT}"
RUN_ROOT="$(cd "${RUN_ROOT}" && pwd)"
CIRCUIT_FOLDER="${RUN_ROOT}/circuit"

COORDINATOR="${RUN_ROOT}/coordinator"
NODE1="${RUN_ROOT}/node1"
NODE2="${RUN_ROOT}/node2"
RESULT="${RUN_ROOT}/result"

PHASE1_INIT="${COORDINATOR}/phase1_init"
NODE1_PHASE1="${NODE1}/phase1"
NODE2_PHASE1="${NODE2}/phase1"
PHASE1_OUTPUT="${COORDINATOR}/phase1_output"

PHASE2_INIT="${COORDINATOR}/phase2_init"
NODE1_PHASE2="${NODE1}/phase2"
NODE2_PHASE2="${NODE2}/phase2"

mkdir -p \
  "${COORDINATOR}" "${NODE1}" "${NODE2}" "${RESULT}" "${CIRCUIT_FOLDER}" \
  "${PHASE1_INIT}" "${NODE1_PHASE1}" "${NODE2_PHASE1}" "${PHASE1_OUTPUT}" \
  "${PHASE2_INIT}" "${NODE1_PHASE2}" "${NODE2_PHASE2}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

run_ceremony() {
  (cd "${RUST_ROOT}" && cargo run --release -p ceremony -- "$@")
}

# Positional args for `ceremony`:
# - phase 0: <circuit-folder>
# - phase 1: <circuit-folder> <output-folder>
# - phase 2: <circuit-folder> <input-folder> <output-folder>
# - phase 3: <circuit-folder> <phase1-input-folder> <phase1-output-folder> <phase2-output-folder>
# - phase 4: <circuit-folder> <input-folder> <output-folder>
# - phase 5: <circuit-folder> <phase1-input-folder> <phase1-output-folder> <phase2-input-folder> <output-folder>
# - phase 6: <input-srs-folder> <output-srs-folder>
# - phase 7: <input-srs-folder> <output-srs-folder>

echo "[1/7] extract_circuit_r1cs_config"
run_ceremony \
  0 \
  "${CIRCUIT_FOLDER}"

echo "[2/7] create_init_srs_phase1"
run_ceremony \
  1 \
  "${CIRCUIT_FOLDER}" \
  "${PHASE1_INIT}"

echo "[3/7] update_srs_phase1 (update #1)"
run_ceremony \
  2 \
  "${CIRCUIT_FOLDER}" \
  "${PHASE1_INIT}" \
  "${NODE1_PHASE1}"

echo "[4/7] update_srs_phase1 (update #2)"
run_ceremony \
  2 \
  "${CIRCUIT_FOLDER}" \
  "${NODE1_PHASE1}" \
  "${NODE2_PHASE1}"

echo "[5/7] specialize_srs"
run_ceremony \
  3 \
  "${CIRCUIT_FOLDER}" \
  "${NODE2_PHASE1}" \
  "${PHASE1_OUTPUT}" \
  "${PHASE2_INIT}"

echo "[6/7] update_srs_phase2 (update #1)"
run_ceremony \
  4 \
  "${CIRCUIT_FOLDER}" \
  "${PHASE2_INIT}" \
  "${NODE1_PHASE2}"

echo "[7/7] update_srs_phase2 (update #2)"
run_ceremony \
  4 \
  "${CIRCUIT_FOLDER}" \
  "${NODE1_PHASE2}" \
  "${NODE2_PHASE2}"

echo "[final] finish_groth_setup"
run_ceremony \
  5 \
  "${CIRCUIT_FOLDER}" \
  "${NODE2_PHASE1}" \
  "${PHASE1_OUTPUT}" \
  "${NODE2_PHASE2}" \
  "${RESULT}"

echo "[verify] verify_transcript_phase1 (node1)"
run_ceremony \
  6 \
  "${PHASE1_INIT}" \
  "${NODE1_PHASE1}"

echo "[verify] verify_transcript_phase1 (node2)"
run_ceremony \
  6 \
  "${NODE1_PHASE1}" \
  "${NODE2_PHASE1}"

echo "[verify] verify_transcript_phase2 (node1)"
run_ceremony \
  7 \
  "${PHASE2_INIT}" \
  "${NODE1_PHASE2}"

echo "[verify] verify_transcript_phase2 (node2)"
run_ceremony \
  7 \
  "${NODE1_PHASE2}" \
  "${NODE2_PHASE2}"

echo "Ceremony completed. Output written to: ${RESULT}"
