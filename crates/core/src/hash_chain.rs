// Copyright 2025 Irreducible Inc.
use crate::{
    Param,
    hash::{Hash, tweak_hash_chain},
};

/// Returns the last hash in the hash chain.
///
/// A hash chain is a sequence of values where each value is computed by hashing the previous one:
///
/// ```plain
/// start → H(start) → H(H(start)) → H(H(H(start))) → ... → end
/// ```
///
/// So this function essentially takes the starting hash and computes the hash chain until the end
/// and returns the last hash in the chain.
///
/// Because we use a tweak hash function, we have to specifically keep track where in the chain
/// we are to correctly form the input to the hash function.
pub fn hash_chain(
    param: &Param,
    chain_index: usize,
    start_hash: Hash,
    start_pos: usize,
    steps: usize,
) -> Hash {
    let mut current = start_hash;
    for j in 0..steps {
        let pos_in_chain = start_pos + j + 1;
        current = tweak_hash_chain(param, chain_index, pos_in_chain, current);
    }
    current
}
