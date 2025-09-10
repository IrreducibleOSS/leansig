// Copyright 2025 Irreducible Inc.
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use leansig_core::spec::{Spec, SPEC_1, SPEC_2};
use leansig_shared::{create_test_data, XmssTestData};
use sp1_sdk::{ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!(
    "../../../../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/sp1-guest"
);

/// Configuration parameters for benchmarking
struct BenchmarkConfig {
    num_validators: usize,
    tree_height: usize,
    spec: Spec,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            num_validators: 16,
            tree_height: 13,
            spec: SPEC_2,
        }
    }
}

impl BenchmarkConfig {
    fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("BENCH_VALIDATORS") {
            if let Ok(n) = val.parse() {
                config.num_validators = n;
            }
        }

        if let Ok(val) = std::env::var("BENCH_TREE_HEIGHT") {
            if let Ok(h) = val.parse() {
                config.tree_height = h;
            }
        }

        if let Ok(val) = std::env::var("BENCH_SPEC") {
            config.spec = match val.as_str() {
                "1" | "SPEC_1" => SPEC_1,
                "2" | "SPEC_2" => SPEC_2,
                _ => SPEC_2,
            };
        }

        config
    }
}

/// Job structure for benchmarking XMSS signatures with SP1
struct Job {
    test_data: XmssTestData,
}

impl Job {
    fn new(config: BenchmarkConfig) -> Self {
        // Create test data with specified parameters
        let test_data = create_test_data(
            config.num_validators,
            config.spec.clone(),
            config.tree_height,
            10000, // max_retries for nonce grinding
            None,  // use default message [42; 32]
            None,  // use default epoch 0
        );

        Self { test_data }
    }

    /// Execute witness generation phase (SP1 setup + stdin preparation)
    fn exec_compute(&self) -> SP1Stdin {
        let mut stdin = SP1Stdin::new();
        stdin.write(&self.test_data);

        stdin
    }
}

/// Main benchmarking function
fn xmss_benchmarks(c: &mut Criterion) {
    let config = BenchmarkConfig::from_env();

    println!("\n════════════════════════════════════════════════");
    println!("SP1 XMSS Signature Benchmark Configuration:");
    println!("  Validators: {}", config.num_validators);
    println!(
        "  Tree Height: {} (max {} signatures)",
        config.tree_height,
        1 << config.tree_height
    );
    println!(
        "  Spec: {}",
        if config.spec.target_sum == SPEC_1.target_sum {
            "SPEC_1"
        } else {
            "SPEC_2"
        }
    );
    println!("════════════════════════════════════════════════\n");

    // Setup client and keys once for all benchmarks
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(ELF);

    let mut group = c.benchmark_group("sp1_xmss_signature");

    // Configure the benchmark group
    group.sample_size(100);

    let job = Job::new(config);

    // Benchmark 1: Witness Generation (setup + stdin preparation)
    group.bench_function("witness_generation", |b| {
        b.iter(|| {
            let stdin = job.exec_compute();
            black_box(stdin);
        });
    });

    // Reset group configuration for proof generation
    group.finish();

    // Create new group for proof generation benchmarks
    let mut group = c.benchmark_group("sp1_xmss_signature_proving");
    group.sample_size(10);

    // Pre-compute stdin once - it gets cloned internally by SP1, not consumed
    let mut stdin = SP1Stdin::new();
    stdin.write(&job.test_data);

    // Benchmark 2: Proof Generation
    group.bench_function("proof_generation", |b| {
        b.iter(|| {
            let proof = client.prove(&pk, &stdin).run().unwrap();
            black_box(proof);
        });
    });

    // Generate proof for verification benchmark (reuse the same stdin)
    let proof = client.prove(&pk, &stdin).run().unwrap();

    group.finish();

    // Create new group for verification benchmarks
    let mut group = c.benchmark_group("sp1_xmss_signature_verification");
    group.sample_size(100); // Many samples for quick operation

    group.bench_function("proof_verification", |b| {
        b.iter(|| {
            client.verify(&proof, &vk).unwrap();
        });
    });

    // Print additional metrics
    println!("\nSP1 Additional Metrics:");
    let proof_size_bytes = bincode::serialize(&proof).unwrap().len();
    println!(
        "  Proof Size: {:.2} KiB ({} bytes)",
        proof_size_bytes as f64 / 1024.0,
        proof_size_bytes
    );

    group.finish();
}

criterion_group!(sp1_xmss_signature, xmss_benchmarks);
criterion_main!(sp1_xmss_signature);
