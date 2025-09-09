// Copyright 2025 Irreducible Inc.
use leansig_core::AggregatedVerifier;
use leansig_shared::XmssTestData;
use risc0_zkvm::guest::env;

fn main() {
    // Read the test data containing both public inputs and aggregated signature
    let test_data: XmssTestData = env::read();
    
    // Extract the components
    let public_inputs = test_data.public_inputs;
    let aggregated_signature = test_data.aggregated_signature;

    // Create the aggregated verifier with the validator roots
    let verifier = AggregatedVerifier::new(
        public_inputs.validator_roots.clone(),
        public_inputs.spec.clone(),
    );

    // Verify the aggregated signature
    let verification_result = verifier.verify(&public_inputs.message, &aggregated_signature);

    // The verification must succeed, otherwise the proof generation will fail
    assert!(verification_result, "XMSS signature verification failed");

    // Commit the public inputs to the journal for the host to verify
    // This ensures the proof is bound to specific inputs
    env::commit(&public_inputs);

    // Optionally commit a success flag
    env::commit(&verification_result);
}
