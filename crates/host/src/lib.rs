use methods::{XMSS_AGGREGATE_ELF, XMSS_AGGREGATE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::time::{Duration, Instant};
use leansig_core::{
    AggregatedSignature, Message, Signer, ValidatorSignature, spec::Spec
};
use rand::{rngs::StdRng, SeedableRng};

/// Public inputs for XMSS aggregate verification
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub message: Message,
    pub epoch: usize,
    pub validator_roots: Vec<leansig_core::hash::Hash>,
    pub validator_params: Vec<leansig_core::Param>,
    pub spec: Spec,
}

pub struct ProveResult {
    pub witness_generation_time: Duration,
    pub proof_generation_time: Duration,
    pub verification_time: Duration,
    pub proof_size_bytes: usize,
    pub receipt: Receipt,
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
/// A tuple of (PublicInputs, AggregatedSignature) for testing
pub fn create_test_data(
    num_validators: usize,
    spec: Spec,
    tree_height: usize,
    max_retries: usize,
    message: Option<Message>,
    epoch: Option<usize>,
) -> (PublicInputs, AggregatedSignature) {
    let message = message.unwrap_or(Message([42; 32]));
    let epoch = epoch.unwrap_or(0);
    
    // Calculate lifetime from tree height (2^height)
    let lifetime = 1 << tree_height;

    let mut validators: Vec<Signer> = (0..num_validators)
        .map(|i| Signer::new(
            StdRng::seed_from_u64(i as u64 + 1),
            max_retries,
            spec.clone(),
            lifetime,
        ))
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

    let aggregated = AggregatedSignature::new(validator_signatures);

    let public_inputs = PublicInputs {
        message,
        epoch,
        validator_roots,
        validator_params,
        spec,
    };

    (public_inputs, aggregated)
}

pub fn prove_xmss_aggregate(input: u32) -> Result<ProveResult, Box<dyn std::error::Error>> {
    // Measure witness generation time
    let witness_start = Instant::now();
    let env = ExecutorEnv::builder()
        .write(&input)?
        .build()?;
    let witness_generation_time = witness_start.elapsed();

    // Get the prover
    let prover = default_prover();

    // Measure proof generation time
    let proof_start = Instant::now();
    let prove_info = prover.prove(env, XMSS_AGGREGATE_ELF)?;
    let proof_generation_time = proof_start.elapsed();

    // Extract the receipt
    let receipt = prove_info.receipt;

    // Calculate proof size
    let proof_size_bytes = if let Ok(succinct) = receipt.inner.succinct() {
        succinct.seal_size()
    } else {
        // For non-succinct receipts, estimate size from the full receipt
        bincode::serialize(&receipt).unwrap_or_default().len()
    };

    // Measure verification time
    let verify_start = Instant::now();
    receipt.verify(XMSS_AGGREGATE_ID)?;
    let verification_time = verify_start.elapsed();

    Ok(ProveResult {
        witness_generation_time,
        proof_generation_time,
        verification_time,
        proof_size_bytes,
        receipt,
    })
}

pub fn prove_xmss_aggregate_with_prover_opts(
    input: u32,
    prover_opts: &ProverOpts,
) -> Result<ProveResult, Box<dyn std::error::Error>> {
    // Measure witness generation time
    let witness_start = Instant::now();
    let env = ExecutorEnv::builder()
        .write(&input)?
        .build()?;
    let witness_generation_time = witness_start.elapsed();

    // Get the prover with specific options
    let prover = risc0_zkvm::get_prover_server(prover_opts)?;

    // Measure proof generation time
    let proof_start = Instant::now();
    let prove_info = prover.prove(env, XMSS_AGGREGATE_ELF)?;
    let proof_generation_time = proof_start.elapsed();

    // Extract the receipt
    let receipt = prove_info.receipt;

    // Calculate proof size
    let proof_size_bytes = if let Ok(succinct) = receipt.inner.succinct() {
        succinct.seal_size()
    } else {
        // For non-succinct receipts, estimate size from the full receipt
        bincode::serialize(&receipt).unwrap_or_default().len()
    };

    // Measure verification time
    let verify_start = Instant::now();
    receipt.verify(XMSS_AGGREGATE_ID)?;
    let verification_time = verify_start.elapsed();

    Ok(ProveResult {
        witness_generation_time,
        proof_generation_time,
        verification_time,
        proof_size_bytes,
        receipt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use leansig_core::spec::SPEC_1;

    #[test]
    fn test_create_test_data_with_custom_height() {
        // Test with tree height 8 (256 signatures)
        let (public_inputs, aggregated) = create_test_data(2, SPEC_1, 8, 10000, None, None);
        assert_eq!(public_inputs.validator_roots.len(), 2);
        assert_eq!(aggregated.signatures.len(), 2);
        
        // Test with tree height 10 (1024 signatures)
        let (public_inputs, aggregated) = create_test_data(3, SPEC_1, 10, 10000, None, None);
        assert_eq!(public_inputs.validator_roots.len(), 3);
        assert_eq!(aggregated.signatures.len(), 3);
    }
    
    #[test]
    fn test_create_test_data_with_defaults() {
        // Test with default tree height 13 (8192 signatures)
        let (public_inputs, aggregated) = create_test_data(4, SPEC_1, 13, 10000, None, None);
        assert_eq!(public_inputs.validator_roots.len(), 4);
        assert_eq!(aggregated.signatures.len(), 4);
    }
    
    #[test]
    fn test_create_test_data_with_custom_message() {
        // Test with custom message
        let custom_message = Message([99; 32]);
        let (public_inputs, aggregated) = create_test_data(
            2, 
            SPEC_1, 
            8, 
            10000, 
            Some(custom_message.clone()), 
            None
        );
        assert_eq!(public_inputs.message.0, custom_message.0);
        assert_eq!(public_inputs.validator_roots.len(), 2);
    }
    
    #[test]
    fn test_create_test_data_with_custom_epoch() {
        // Test with custom epoch
        let custom_epoch = 5;
        let (public_inputs, aggregated) = create_test_data(
            2,
            SPEC_1,
            8,
            10000,
            None,
            Some(custom_epoch)
        );
        assert_eq!(public_inputs.epoch, custom_epoch);
        assert_eq!(aggregated.signatures[0].epoch, custom_epoch);
    }
}
