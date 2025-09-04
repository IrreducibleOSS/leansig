use leansig_core::{Message, Param, hash::Hash, spec::Spec};
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
    /// Domain parameters (one per validator)
    pub validator_params: Vec<Param>,
    /// The specification for the signature scheme
    pub spec: Spec,
}
