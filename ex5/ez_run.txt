#!/usr/bin/env bash
set -euo pipefail

# ---- config (edit if your paths differ) ----
PIN_ROOT="/home/ubuntu/Documents/pin-3.30-98830-g1d7b601b3-gcc-linux"
SIMPLE_EX="${PIN_ROOT}/source/tools/SimpleExamples"
EX5_DIR="/home/ubuntu/Documents/Binary_translation/ex5"
PIN_BIN="${PIN_ROOT}/pin"

# ---- args ----
if [[ $# -ne 1 || "${1##*.}" != "cpp" ]]; then
  echo "usage: $0 <file>.cpp" >&2
  exit 1
fi
SRC_CPP="$(realpath "$1")"
BASE="$(basename "$SRC_CPP" .cpp)"

echo "==> git pull in ${EX5_DIR}"
git -C "${EX5_DIR}" pull --rebase

echo "==> copy ${SRC_CPP} -> ${SIMPLE_EX}"
cp -f "${SRC_CPP}" "${SIMPLE_EX}/"

echo "==> build ${BASE}.test in ${SIMPLE_EX}"
cd "${SIMPLE_EX}"
make "${BASE}.test"

echo "==> copy built .so to ${EX5_DIR}"
OBJ_DIR="${SIMPLE_EX}/obj-intel64"
SO_SRC="${OBJ_DIR}/${BASE}.so"
if [[ ! -f "${SO_SRC}" ]]; then
  echo "error: expected ${SO_SRC} not found" >&2
  exit 2
fi
cp -f "${SO_SRC}" "${EX5_DIR}/"

echo "==> run pin with ${BASE}.so in ${EX5_DIR}"
cd "${EX5_DIR}"
time "${PIN_BIN}" -t "${BASE}.so" -create_tc2 -prof_time 4 -- ./cc1 expr.i
