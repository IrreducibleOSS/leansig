use leansig_core::{Message, Param, hash::Hash, spec::Spec, AggregatedSignature};
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
