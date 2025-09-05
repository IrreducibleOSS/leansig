#!/bin/bash

# RISC0 XMSS Benchmark Script with CUDA Support
# This script runs benchmarks with CUDA acceleration if available

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║      XMSS Aggregate Benchmark Suite (CUDA)          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo

# Check if CUDA is available
if command -v nvidia-smi &> /dev/null; then
    echo "✅ NVIDIA GPU detected:"
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
    echo
else
    echo "⚠️  No NVIDIA GPU detected. Will run on CPU."
    echo
fi

# Set environment variables for optimal RISC0 performance
export RUST_LOG=info
export RISC0_PROVER=local  # Use local prover
export RISC0_GPU_SPLIT_FACTOR=1  # Use single GPU if available

echo "📦 Building with CUDA support..."
cargo build --release --features cuda -p host

echo
echo "🚀 Running benchmarks with CUDA acceleration..."
echo "   Sample size: 10 iterations per benchmark"
echo

# Run the Criterion benchmark
cargo bench --features cuda -p host

echo
echo "📊 Benchmark results saved to:"
echo "   target/criterion/index.html"
echo
echo "✅ Benchmark complete!"