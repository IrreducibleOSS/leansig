// Copyright 2025 Irreducible Inc.
use leansig_core::{spec, AggregatedVerifier};
use leansig_shared::create_test_data;
use sp1_sdk::{ProverClient, SP1Stdin};
use tracing_subscriber;

const ELF: &[u8] = include_bytes!(
    "../../../../target/elf-compilation/riscv32im-succinct-zkvm-elf/release/sp1-guest"
);

fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let test_data = create_test_data(3, spec::SPEC_2, 13, 10000, None, None);

    // Sanity check the signature verification
    let verifier = AggregatedVerifier::new(
        test_data.public_inputs.validator_roots.clone(),
        test_data.public_inputs.spec.clone(),
    );
    assert!(
        verifier.verify(
            &test_data.public_inputs.message,
            &test_data.aggregated_signature
        ),
        "failed to verify aggregated signature"
    );

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&test_data);

    println!("Generated proof");

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, &stdin).run().unwrap();

    println!("Successfully generated proof!");

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Get the public values from the proof as committed by the guest.
    let _committed_public_inputs = proof.public_values.read::<leansig_shared::PublicInputs>();
    let committed_verification_result = proof.public_values.read::<bool>();

    println!("Verification result: {}", committed_verification_result);
    assert!(committed_verification_result, "Guest verification failed");

    println!("Successfully verified proof!");
}
