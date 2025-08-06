//! Definition of various tweaked hash functions used in the project.

use sha2::{Digest as _, Sha256};

use crate::{Message, Param};

// Taken from:
// https://github.com/b-wagn/hash-sig/blob/34fa36886d2942f851f26345c49f92fdb96ac7eb/src/lib.rs#L4-L6
const TWEAK_CHAIN: u8 = 0x00;
const TWEAK_MESSAGE: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash(pub [u8; 32]);

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// TODO: this is not the same function used in the upstream hash-sig repo, because it still lacks
// 2 parameters:
// - randomness
// - epoch.
pub fn tweak_hash_message(param: &Param, message: &Message) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(param);
    hasher.update([TWEAK_MESSAGE]);
    hasher.update(message);
    let hash = hasher.finalize();
    Hash(hash.into())
}

/// Returns a hash that is meant to be used for chain hash.
///
// TODO: same here:
// - epoch
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
