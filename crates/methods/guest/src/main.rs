use leansig_core::{AggregatedSignature, AggregatedVerifier};
use leansig_shared::PublicInputs;
use risc0_zkvm::guest::env;

fn main() {
    // Read the public inputs and aggregated signature separately
    let public_inputs: PublicInputs = env::read();
    let aggregated_signature: AggregatedSignature = env::read();

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
