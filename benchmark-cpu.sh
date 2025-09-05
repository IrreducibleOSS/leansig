#!/bin/bash

# RISC0 XMSS Benchmark Script (CPU Only)
# This script runs benchmarks without CUDA acceleration

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║       XMSS Aggregate Benchmark Suite (CPU)          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo

# Set environment variables for optimal RISC0 performance
export RUST_LOG=info
export RISC0_PROVER=local  # Use local prover

echo "📦 Building without CUDA support..."
cargo build --release -p host

echo
echo "💻 Running benchmarks on CPU..."
echo "   Sample size: 10 iterations per benchmark"
echo

# Run the Criterion benchmark
cargo bench -p host

echo
echo "📊 Benchmark results saved to:"
echo "   target/criterion/index.html"
echo
echo "✅ Benchmark complete!"