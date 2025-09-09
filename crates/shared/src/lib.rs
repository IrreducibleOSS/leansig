// Copyright 2025 Irreducible Inc.
use leansig_core::{
    AggregatedSignature, Message, Param, Signer, ValidatorSignature, hash::Hash, spec::Spec,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};

/// Public inputs for RISC0 proof - only this gets committed to the journal
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    /// The message being signed by all validators
    pub message: Message,
    /// The epoch at which all validators sign
    pub epoch: usize,
    /// Each validator's XMSS tree root hash
    pub validator_roots: Vec<Hash>,
    /// Domain parameters for each validator
    pub validator_params: Vec<Param>,
    /// Specification for the signature scheme
    pub spec: Spec,
}

/// Test data structure containing both public inputs and the aggregated signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XmssTestData {
    pub public_inputs: PublicInputs,
    pub aggregated_signature: AggregatedSignature,
}

/// Create test data for XMSS aggregate signatures
///
/// # Arguments
/// * `num_validators` - Number of validators to create
/// * `spec` - Specification for the signature scheme
/// * `tree_height` - Height of the XMSS tree (determines number of signatures = 2^height). Default is 13.
/// * `max_retries` - Maximum number of retries for nonce grinding. Default is 10000.
/// * `message` - Optional message to sign. Defaults to [42; 32].
/// * `epoch` - Epoch for signing. Default is 0.
///
/// # Returns
/// An XmssTestData struct containing both public inputs and aggregated signature
pub fn create_test_data(
    num_validators: usize,
    spec: Spec,
    tree_height: usize,
    max_retries: usize,
    message: Option<Message>,
    epoch: Option<usize>,
) -> XmssTestData {
    let message = message.unwrap_or(Message([42; 32]));
    let epoch = epoch.unwrap_or(0);

    // Calculate lifetime from tree height (2^height)
    let lifetime = 1 << tree_height;

    let mut validators: Vec<Signer> = (0..num_validators)
        .map(|i| {
            Signer::new(
                StdRng::seed_from_u64(i as u64 + 1),
                max_retries,
                spec.clone(),
                lifetime,
            )
        })
        .collect();

    let validator_roots: Vec<_> = validators.iter().map(|v| v.root.clone()).collect();
    let validator_params: Vec<_> = validators.iter().map(|v| v.param.clone()).collect();

    // Each validator signs the message
    let validator_signatures: Vec<ValidatorSignature> = validators
        .iter_mut()
        .map(|validator| {
            let signature = validator.sign(epoch, &message).expect("Failed to sign");
            ValidatorSignature {
                epoch,
                signature,
                xmss_root: validator.root.clone(),
                param: validator.param.clone(),
            }
        })
        .collect();

    let aggregated_signature = AggregatedSignature::new(validator_signatures);

    XmssTestData {
        public_inputs: PublicInputs {
            message,
            epoch,
            validator_roots,
            validator_params,
            spec,
        },
        aggregated_signature,
    }
}
