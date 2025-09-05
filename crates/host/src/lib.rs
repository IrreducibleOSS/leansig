use leansig_core::{
    AggregatedSignature, Message, Signer, ValidatorSignature, spec::Spec
};
use leansig_shared::XmssTestData;
use rand::{rngs::StdRng, SeedableRng};

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

    let aggregated_signature = AggregatedSignature::new(validator_signatures);

    XmssTestData {
        public_inputs: leansig_shared::PublicInputs {
            message,
            epoch,
            validator_roots,
            validator_params,
            spec,
        },
        aggregated_signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leansig_core::spec::SPEC_1;

    #[test]
    fn test_create_test_data_with_custom_height() {
        // Test with tree height 8 (256 signatures)
        let test_data = create_test_data(2, SPEC_1, 8, 10000, None, None);
        assert_eq!(test_data.public_inputs.validator_roots.len(), 2);
        assert_eq!(test_data.aggregated_signature.signatures.len(), 2);
        
        // Test with tree height 10 (1024 signatures)
        let test_data = create_test_data(3, SPEC_1, 10, 10000, None, None);
        assert_eq!(test_data.public_inputs.validator_roots.len(), 3);
        assert_eq!(test_data.aggregated_signature.signatures.len(), 3);
    }
    
    #[test]
    fn test_create_test_data_with_defaults() {
        // Test with default tree height 13 (8192 signatures)
        let test_data = create_test_data(4, SPEC_1, 13, 10000, None, None);
        assert_eq!(test_data.public_inputs.validator_roots.len(), 4);
        assert_eq!(test_data.aggregated_signature.signatures.len(), 4);
    }
    
    #[test]
    fn test_create_test_data_with_custom_message() {
        // Test with custom message
        let custom_message = Message([99; 32]);
        let test_data = create_test_data(
            2, 
            SPEC_1, 
            8, 
            10000, 
            Some(custom_message.clone()), 
            None
        );
        assert_eq!(test_data.public_inputs.message.0, custom_message.0);
        assert_eq!(test_data.public_inputs.validator_roots.len(), 2);
    }
    
    #[test]
    fn test_create_test_data_with_custom_epoch() {
        // Test with custom epoch
        let custom_epoch = 5;
        let test_data = create_test_data(
            2,
            SPEC_1,
            8,
            10000,
            None,
            Some(custom_epoch)
        );
        assert_eq!(test_data.public_inputs.epoch, custom_epoch);
        assert_eq!(test_data.aggregated_signature.signatures[0].epoch, custom_epoch);
    }
}
