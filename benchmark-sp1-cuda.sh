#!/bin/bash
# Copyright 2025 Irreducible Inc.

# SP1 XMSS Benchmark Script with CUDA Support
# This script runs benchmarks with CUDA acceleration if available

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║      SP1 XMSS Aggregate Benchmark Suite (CUDA)      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo

# Check if CUDA is available
if ! command -v nvidia-smi &> /dev/null; then
    echo "❌ No NVIDIA GPU detected. This script requires a GPU."
    echo "   Please run on a GPU-enabled instance."
    exit 1
fi

echo "✅ NVIDIA GPU detected:"
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
echo

# Set environment variables for SP1 CUDA proving
export SP1_PROVER=cuda
export CUDA_VISIBLE_DEVICES=0
<<<<<<< HEAD
export RUST_LOG=info
=======
export RUST_LOG=warn
>>>>>>> cd68652 (pedantic)
export SP1_CUDA=1
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2"

echo "🎯 SP1 CUDA environment configured:"
echo "   SP1_PROVER=$SP1_PROVER"
echo "   CUDA_VISIBLE_DEVICES=$CUDA_VISIBLE_DEVICES"
echo "   SP1_CUDA=$SP1_CUDA"
echo

echo "🔨 Building SP1 guest program..."
cd crates/sp1/guest
cargo prove build
cd ../../..

echo "📦 Building SP1 host for CUDA..."
cargo build --release -p sp1-host

echo
echo "🚀 Running benchmarks..."
echo "   Sample size: 10 iterations per benchmark"
echo

# Run the Criterion benchmark
cargo bench -p sp1-host

echo
echo "📊 Benchmark results saved to:"
echo "   target/criterion/index.html"
echo
echo "✅ Benchmark complete!"