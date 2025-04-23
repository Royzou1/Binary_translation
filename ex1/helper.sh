#!/bin/bash

# Define paths
PIN_PATH=../../pin-3.30-98830-g1d7b601b3-gcc-linux
PIN_EXAMPLES=$PIN_PATH/source/tools/SimpleExamples
CURRENT_DIR=$(pwd)

# Copy ex1.cpp to Pin's SimpleExamples
cp ex1.cpp "$PIN_EXAMPLES"

# Go to SimpleExamples and build
cd "$PIN_EXAMPLES" || exit 1
make obj-intel64/ex1.so TARGET=intel64 TOOL_ROOTS=ex1

# Copy the built .so file back to original directory
cp obj-intel64/ex1.so "$CURRENT_DIR"

# Return to original directory
cd "$CURRENT_DIR"
echo "Build complete. ex1.so copied back."
