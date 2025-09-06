#![no_main]
sp1_zkvm::entrypoint!(main);

use leansig_core::AggregatedVerifier;
use leansig_shared::XmssTestData;

// Note: This implementation uses SP1's keccak_permute precompile for optimized hashing.
// The optimization is enabled via the "sp1" feature flag in leansig-core, which activates
// tiny-keccak's "succinct" feature. This significantly reduces cycles for XMSS verification
// which is keccak-intensive (using 4 different keccak-based hash functions).

pub fn main() {
    // Read the test data containing both public inputs and aggregated signature
    let test_data = sp1_zkvm::io::read::<XmssTestData>();
    
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
    sp1_zkvm::io::commit(&public_inputs);

    // Optionally commit a success flag
    sp1_zkvm::io::commit(&verification_result);
}