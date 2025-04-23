#!/bin/bash

# Define paths
PIN_PATH=../../pin-3.30-98830-g1d7b601b3-gcc-linux
PIN_EXAMPLES=$PIN_PATH/source/tools/SimpleExamples
CURRENT_DIR=$(pwd)
PIN_BIN=$PIN_PATH/pin

# Step 1: Copy ex1.cpp to Pin examples
echo "[*] Copying ex1.cpp to Pin examples..."
cp ex1.cpp "$PIN_EXAMPLES" || { echo "Failed to copy ex1.cpp"; exit 1; }

# Step 2: Build ex1.so in SimpleExamples
cd "$PIN_EXAMPLES" || exit 1
echo "[*] Building ex1.so with make..."
make ex1.test || { echo "Build failed"; exit 1; }

# Step 3: Copy .so back to original directory
echo "[*] Copying ex1.so back to working directory..."
cp obj-intel64/ex1.so "$CURRENT_DIR"

# Step 4: Return to working directory
cd "$CURRENT_DIR"

# Step 5: Run pintool with tst binary if available
if [[ -f "tst" ]]; then
    echo "[*] Running pintool on ./tst"
    time "$PIN_BIN" -t ex1.so -- ./tst
else
    echo "[!] 'tst' binary not found. Skipping test run."
fi

# Step 6: Output result status
if [[ -f "rtn-output.csv" ]]; then
    echo "[✓] Output file generated: rtn-output.csv"
else
    echo "[!] No output file generated."
fi
