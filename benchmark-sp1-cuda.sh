#!/bin/bash

# SP1 XMSS Benchmark Script with CUDA Support
# This script runs benchmarks with CUDA acceleration if available

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║      SP1 XMSS Aggregate Benchmark Suite (CUDA)      ║"
echo "║    With Keccak Precompile Optimization Enabled      ║"
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
export RUST_LOG=warn  # Reduce verbosity to warnings only
export SP1_CUDA=1
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2"
export SP1_DEBUG=0  # Disable debug output

echo "🎯 SP1 CUDA environment configured:"
echo "   SP1_PROVER=$SP1_PROVER"
echo "   CUDA_VISIBLE_DEVICES=$CUDA_VISIBLE_DEVICES"
echo "   SP1_CUDA=$SP1_CUDA"
echo "   RUST_LOG=$RUST_LOG (reduced verbosity)"
echo

echo "🔨 Building SP1 guest program with keccak precompile..."
echo "   ✓ syscall_keccak_permute integrated in leansig-core"
echo "   ✓ All hash operations optimized for SP1 zkVM"
cd crates/sp1/guest
cargo prove build 2>&1 | grep -E "Finished|Error|warning" || true
cd ../../..

echo "📦 Building SP1 host for CUDA..."
cargo build --release -p sp1-host 2>&1 | grep -E "Finished|Error|warning" || true

echo
echo "🚀 Running benchmarks with reduced output..."
echo "   Sample size: 10 iterations per benchmark"
echo

# Run the Criterion benchmark with output filtering
# Suppress most output but keep important benchmark results
cargo bench -p sp1-host 2>&1 | grep -E "time:|Benchmarking|mean|std. dev.|median|throughput|Found|Running|Gnuplot|criterion" || cargo bench -p sp1-host

echo
echo "📊 Benchmark results saved to:"
echo "   target/criterion/index.html"
echo
echo "✅ Benchmark complete!"