use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    /// The message being signed by all validators
    pub message: [u8; 32],
    /// The epoch at which all validators sign
    pub epoch: u32,
    /// Each validator's XMSS tree root hash
    pub validator_roots: Vec<[u8; 32]>,
    /// Domain parameters (one per validator to match monbijou-get)
    pub validator_params: Vec<Vec<u8>>,
}