// Copyright 2025 Irreducible Inc.
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use leansig_core::spec::{SPEC_1, SPEC_2, Spec};
use leansig_shared::{XmssTestData, create_test_data};
use methods::{XMSS_AGGREGATE_ELF, XMSS_AGGREGATE_ID};
use risc0_zkvm::{
    ExecutorEnv, ExecutorImpl, ProverOpts, Session, VerifierContext, get_prover_server,
};

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

/// Job structure for benchmarking XMSS signatures
struct Job {
    elf: Vec<u8>,
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

        Self {
            elf: XMSS_AGGREGATE_ELF.to_vec(),
            test_data,
        }
    }

    /// Execute witness generation phase
    fn exec_compute(&self) -> Session {
        let env = ExecutorEnv::builder()
            .write(&self.test_data)
            .unwrap()
            .build()
            .unwrap();

        let mut exec = ExecutorImpl::from_elf(env, &self.elf).unwrap();
        exec.run().unwrap()
    }
}

/// Main benchmarking function
fn xmss_benchmarks(c: &mut Criterion) {
    let config = BenchmarkConfig::from_env();

    println!("\n════════════════════════════════════════════════");
    println!("XMSS Signature Benchmark Configuration:");
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

    // Setup prover and verifier context once for all benchmarks
    let prover = get_prover_server(&ProverOpts::succinct()).unwrap();
    let ctx = VerifierContext::default();

    let mut group = c.benchmark_group("xmss_signature");
    group.sample_size(100);

    let job = Job::new(config);

    // Benchmark 1: Witness Generation
    group.bench_function("witness_generation", |b| {
        b.iter(|| {
            let session = job.exec_compute();
            black_box(session);
        });
    });

    // Pre-compute session for proving/verification benchmarks
    let session = job.exec_compute();

    // Reset group configuration for proof generation
    group.finish();

    // Create new group for proof generation benchmarks
    let mut group = c.benchmark_group("xmss_signature_proving");
    group.sample_size(10);

    // Benchmark 2: Proof Generation (Succinct only)
    group.bench_function("proof_generation", |b| {
        b.iter(|| {
            let receipt = prover.prove_session(&ctx, &session).unwrap().receipt;
            black_box(receipt);
        });
    });

    // Generate succinct receipt for verification benchmark
    let receipt = prover.prove_session(&ctx, &session).unwrap().receipt;

    group.finish();

    // Create new group for verification benchmarks
    let mut group = c.benchmark_group("xmss_signature_verification");
    group.sample_size(100); // Many samples for quick operation

    group.bench_function("proof_verification", |b| {
        b.iter(|| {
            receipt.verify(XMSS_AGGREGATE_ID).unwrap();
        });
    });

    // Print additional metrics
    println!("\nAdditional Metrics:");
    println!("  Total Cycles: {}", session.total_cycles);
    println!("  User Cycles: {}", session.user_cycles);
    println!("  Journal Size: {} bytes", receipt.journal.bytes.len());

    if let Ok(succinct) = receipt.inner.succinct() {
        println!(
            "  Succinct Proof Size: {:.2} KiB ({} bytes)",
            succinct.seal_size() as f64 / 1024.0,
            succinct.seal_size()
        );
    }

    group.finish();
}

criterion_group!(xmss_signature, xmss_benchmarks);
criterion_main!(xmss_signature);
