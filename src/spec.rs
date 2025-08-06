/// Specification for the signature scheme instantiation.
#[derive(Clone, Debug)]
pub struct Spec {
    /// The number of bits per chunk.
    pub chunk_bits: usize,
    /// The number of chunks in a codeword.
    ///
    /// Also number of chunks.
    pub num_chains: usize,
    /// The length of the parameter for hashing.
    pub param_len: usize,
    /// The sum of all coordinates of a vertex of a signature that we accept.
    pub target_sum: usize,
}

impl Spec {
    /// Returns the number of chains (same as num_chunks).
    pub fn num_chains(&self) -> usize {
        self.num_chains
    }

    /// Returns the chain length (2^chunk_bits).
    pub fn chain_len(&self) -> usize {
        1 << self.chunk_bits
    }
}

impl Default for Spec {
    fn default() -> Self {
        let message_hash_len = 18;
        let chunk_bits = 4;
        let num_chains = message_hash_len * 8 / chunk_bits;
        Self {
            chunk_bits,
            num_chains,
            param_len: 18,
            target_sum: 297,
        }
    }
}
