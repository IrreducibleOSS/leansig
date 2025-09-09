// Copyright 2025 Irreducible Inc.
//! Definition of various tweaked hash functions used in the project.

use rand::{RngCore as _, rngs::StdRng};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::{Message, Nonce, Param, Pk};

// Taken from:
// https://github.com/b-wagn/hash-sig/blob/34fa36886d2942f851f26345c49f92fdb96ac7eb/src/lib.rs#L4-L6
const TWEAK_CHAIN: u8 = 0x00;
const TWEAK_TREE: u8 = 0x01;
const TWEAK_MESSAGE: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn random(rng: &mut StdRng) -> Self {
        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        Hash(hash)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub fn tweak_hash_message(param: &Param, message: &Message, nonce: &Nonce) -> Hash {
    let mut hasher = Keccak::v256();
    hasher.update(param.as_ref());
    hasher.update(&[TWEAK_MESSAGE]);
    hasher.update(nonce.as_ref());
    hasher.update(message.as_ref());
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    Hash(hash)
}

/// Returns a hash that is meant to be used for chain hash.
pub fn tweak_hash_chain(
    param: &Param,
    chain_index: usize,
    pos_in_chain: usize,
    hash: Hash,
) -> Hash {
    let mut hasher = Keccak::v256();
    hasher.update(param.as_ref());
    hasher.update(&[TWEAK_CHAIN]);
    hasher.update(hash.as_ref());
    hasher.update(&(chain_index as u64).to_be_bytes());
    hasher.update(&(pos_in_chain as u64).to_be_bytes());
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    Hash(result)
}
/// Computes the hash of a HashTree node from its two children.
///
/// # Arguments
///
/// * `param` - Cryptographic parameter
/// * `left` - Hash of the left child node
/// * `right` - Hash of the right child node  
/// * `level` - The level of this node in the tree (0 = leaf level)
/// * `index` - The index of this node at its level
///
/// # Returns
///
/// The hash of the node
pub fn tweak_hash_tree_node(
    param: &Param,
    left: &Hash,
    right: &Hash,
    level: u32,
    index: u32,
) -> Hash {
    let mut hasher = Keccak::v256();
    hasher.update(param.as_ref());
    hasher.update(&[TWEAK_TREE]);
    hasher.update(&level.to_be_bytes());
    hasher.update(&index.to_be_bytes());
    hasher.update(left.as_ref());
    hasher.update(right.as_ref());
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    Hash(result)
}

/// Computes the hash associated to a public key
///
/// This is used to compute the leaves of the HashTree
///
/// # Arguments
///
/// * `param` - Cryptographic parameter
/// * `public_key` - The public key
pub fn tweak_public_key_hash(param: &Param, public_key: &Pk) -> Hash {
    let mut hasher = Keccak::v256();
    hasher.update(param.as_ref());
    hasher.update(&[TWEAK_TREE]);
    for h in public_key.end_hashes.iter() {
        hasher.update(h.as_ref());
    }
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    Hash(result)
}
