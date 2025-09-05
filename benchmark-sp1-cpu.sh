#!/bin/bash

# SP1 XMSS Benchmark Script (CPU Only)
# This script runs benchmarks without CUDA acceleration

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║       SP1 XMSS Aggregate Benchmark Suite (CPU)      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo

# Set environment variables for optimal SP1 performance
export RUST_LOG=info

echo "🔨 Building SP1 guest program..."
cd crates/sp1/guest
cargo prove build
cd ../../..

echo "📦 Building SP1 host..."
cargo build --release -p sp1-host

echo
echo "💻 Running benchmarks on CPU..."
echo "   Sample size: 10 iterations per benchmark"
echo

# Run the Criterion benchmark
cargo bench -p sp1-host

echo
echo "📊 Benchmark results saved to:"
echo "   target/criterion/index.html"
echo
echo "✅ Benchmark complete!"