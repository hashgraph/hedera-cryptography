#!/usr/bin/env bash
set -euo pipefail

# Runs a sample WRAPS ceremony with:
# - phase 1 updates: 2
# - phase 2 updates: 2
#
# Usage:
#   ceremony/run_sample_ceremony.sh <circuit-folder> <run-root>
#
# Example:
#   ceremony/run_sample_ceremony.sh /tmp/tss/circuit /tmp/tss

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <circuit-folder> <run-root>"
  exit 1
fi

CIRCUIT_FOLDER="$(cd "$1" && pwd)"
RUN_ROOT="$2"

mkdir -p "${RUN_ROOT}"

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
  "${COORDINATOR}" "${NODE1}" "${NODE2}" "${RESULT}" \
  "${PHASE1_INIT}" "${NODE1_PHASE1}" "${NODE2_PHASE1}" "${PHASE1_OUTPUT}" \
  "${PHASE2_INIT}" "${NODE1_PHASE2}" "${NODE2_PHASE2}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

run_ceremony() {
  (cd "${RUST_ROOT}" && cargo run --release -p ceremony -- "$@")
}

echo "[1/6] create_init_srs_phase1"
run_ceremony \
  --phase 1 \
  --circuit-folder "${CIRCUIT_FOLDER}" \
  --output-folder "${PHASE1_INIT}"

echo "[2/6] update_srs_phase1 (update #1)"
run_ceremony \
  --phase 2 \
  --circuit-folder "${CIRCUIT_FOLDER}" \
  --input-folder "${PHASE1_INIT}" \
  --output-folder "${NODE1_PHASE1}"

echo "[3/6] update_srs_phase1 (update #2)"
run_ceremony \
  --phase 2 \
  --circuit-folder "${CIRCUIT_FOLDER}" \
  --input-folder "${NODE1_PHASE1}" \
  --output-folder "${NODE2_PHASE1}"

echo "[4/6] specialize_srs"
run_ceremony \
  --phase 3 \
  --circuit-folder "${CIRCUIT_FOLDER}" \
  --phase1-input-folder "${NODE2_PHASE1}" \
  --phase1-output-folder "${PHASE1_OUTPUT}" \
  --phase2-output-folder "${PHASE2_INIT}"

echo "[5/6] update_srs_phase2 (update #1)"
run_ceremony \
  --phase 4 \
  --circuit-folder "${CIRCUIT_FOLDER}" \
  --input-folder "${PHASE2_INIT}" \
  --output-folder "${NODE1_PHASE2}"

echo "[6/6] update_srs_phase2 (update #2)"
run_ceremony \
  --phase 4 \
  --circuit-folder "${CIRCUIT_FOLDER}" \
  --input-folder "${NODE1_PHASE2}" \
  --output-folder "${NODE2_PHASE2}"

echo "[final] finish_groth_setup"
run_ceremony \
  --phase 5 \
  --phase1-input-folder "${NODE2_PHASE1}" \
  --phase1-output-folder "${PHASE1_OUTPUT}" \
  --phase2-input-folder "${NODE2_PHASE2}" \
  --output-folder "${RESULT}"

echo "Ceremony completed. Output written to: ${RESULT}"
