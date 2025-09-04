use leansig_core::{AggregatedSignature, AggregatedVerifier};
use leansig_shared::PublicInputs;
use risc0_zkvm::guest::env;

fn main() {
    let public_inputs: PublicInputs = env::read();
    let aggregated_signature: AggregatedSignature = env::read();

    let verifier = AggregatedVerifier::new(public_inputs.validator_roots.clone(), public_inputs.spec.clone());

    assert!(
        verifier.verify(&public_inputs.message, &aggregated_signature),
        "Aggregated signature verification failed"
    );

    env::commit(&public_inputs);
}
