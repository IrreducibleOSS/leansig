use serde::{Deserialize, Serialize};
use leansig_core::{Message, AggregatedSignature, spec::Spec};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    /// The message being signed by all validators
    pub message: Message,
    /// The epoch at which all validators sign
    pub epoch: usize,
    /// Each validator's XMSS tree root hash
    pub validator_roots: Vec<leansig_core::hash::Hash>,
    /// Domain parameters for each validator
    pub validator_params: Vec<leansig_core::Param>,
    /// Specification for the signature scheme
    pub spec: Spec,
}

/// Test data structure containing both public inputs and the aggregated signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XmssTestData {
    pub public_inputs: PublicInputs,
    pub aggregated_signature: AggregatedSignature,
}