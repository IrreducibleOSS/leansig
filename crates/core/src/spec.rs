// Copyright 2025 Irreducible Inc.
use serde::{Deserialize, Serialize};

/// Specification for the signature scheme instantiation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Spec {
    pub message_hash_len: usize,
    /// The number of bits per each coordinate in a codeword.
    ///
    /// This is denoted by `w` in the paper or known as chunk size in the reference implementation.
    pub coordinate_resolution_bits: usize,
    /// The length of the parameter for hashing.
    pub param_len: usize,
    /// The sum of all coordinates of a vertex of a signature that we accept.
    pub target_sum: usize,
}

impl Spec {
    /// The dimension of the hypercube.
    ///
    /// This is the same as the number of chains.
    pub fn dimension(&self) -> usize {
        self.message_hash_len * 8 / self.coordinate_resolution_bits
    }

    /// Returns the chain length (2^chunk_bits).
    pub fn chain_len(&self) -> usize {
        1 << self.coordinate_resolution_bits
    }
}

pub const SPEC_1: Spec = Spec {
    message_hash_len: 18,
    coordinate_resolution_bits: 2,
    param_len: 18,
    target_sum: 119,
};

pub const SPEC_2: Spec = Spec {
    message_hash_len: 18,
    coordinate_resolution_bits: 4,
    param_len: 18,
    target_sum: 297,
};
