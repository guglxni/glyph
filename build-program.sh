#!/bin/bash
set -e

# Run from project root
cd "$(dirname "$0")"

echo "Building GLYPH Verifier program using Docker..."

# Use Docker to build in a clean Solana/Rust environment
# This bypasses any local Darwin/Arm toolchain/dependency issues
docker build -t glyph-builder -f programs/glyph-verifier/Dockerfile.build .

# Create target directory if it doesn't exist
mkdir -p programs/glyph-verifier/target/deploy

# Extract the built .so file
CONTAINER_ID=$(docker create glyph-builder)
docker cp $CONTAINER_ID:/build/programs/glyph-verifier/target/deploy/glyph_verifier.so ./programs/glyph-verifier/target/deploy/
docker rm $CONTAINER_ID

echo "Build complete! Artifact is at: programs/glyph-verifier/target/deploy/glyph_verifier.so"
