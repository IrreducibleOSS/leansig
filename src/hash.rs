//! Definition of various tweaked hash functions used in the project.

use rand::{RngCore as _, rngs::StdRng};
use sha2::{Digest as _, Sha256};

use crate::{Message, Param, Rho};

// Taken from:
// https://github.com/b-wagn/hash-sig/blob/34fa36886d2942f851f26345c49f92fdb96ac7eb/src/lib.rs#L4-L6
const TWEAK_CHAIN: u8 = 0x00;
const TWEAK_MESSAGE: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

pub fn tweak_hash_message(param: &Param, message: &Message, rho: &Rho) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(param);
    hasher.update([TWEAK_MESSAGE]);
    hasher.update(&rho.0);
    hasher.update(message);
    let hash = hasher.finalize();
    Hash(hash.into())
}

/// Returns a hash that is meant to be used for chain hash.
pub fn tweak_hash_chain(
    param: &Param,
    chain_index: usize,
    pos_in_chain: usize,
    hash: Hash,
) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(param);
    hasher.update([TWEAK_CHAIN]);
    hasher.update(hash);
    let hash = hasher.finalize();
    Hash(hash.into())
}
