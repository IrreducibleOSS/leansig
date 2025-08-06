//! Encoding related stuff.

use bitvec::prelude::*;
use rand::rngs::StdRng;

use crate::{
    Message, Param, Rho,
    hash::{self, tweak_hash_message},
};

/// Find a suitable encoding to fit into the target sum.
pub fn grind(
    num_chunks: usize,
    chunk_bits: usize,
    target_sum: usize,
    max_retries: usize,
    param: &Param,
    message: &Message,
    rng: &mut StdRng,
) -> Option<(Codeword, Rho)> {
    for _ in 0..max_retries {
        let rho = Rho::random(rng);
        let codeword = Codeword::new(num_chunks, chunk_bits, param, message, &rho);
        if codeword.sum() == target_sum {
            return Some((codeword, rho));
        }
    }

    // give up because we couldn't fnd
    None
}

pub struct Codeword {
    chunks: Vec<u8>,
}

impl Codeword {
    pub fn new(
        num_chunks: usize,
        chunk_bits: usize,
        param: &Param,
        message: &Message,
        rho: &Rho,
    ) -> Codeword {
        let full_hash = tweak_hash_message(param, message);
        let trunc_hash = &full_hash.as_ref()[0..num_chunks * chunk_bits / 8];
        let chunks = bytes_to_chunks(trunc_hash, chunk_bits);
        Self { chunks }
    }

    /// Returns the sum over all the chunks.
    ///
    /// This defines the distance from the sink
    pub fn sum(&self) -> usize {
        self.chunks.iter().map(|&chunk| chunk as usize).sum()
    }

    pub fn num_chunks(&self) -> usize {
        self.chunks.len()
    }

    pub fn chunks(&self) -> &[u8] {
        &self.chunks
    }
}

fn bytes_to_chunks(bytes: &[u8], chunk_bits: usize) -> Vec<u8> {
    assert!(chunk_bits <= 8);
    assert!(chunk_bits.is_power_of_two());
    bytes
        .view_bits::<Lsb0>()
        .chunks_exact(chunk_bits)
        .map(|chunk| chunk.load::<u8>())
        .collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use super::bytes_to_chunks;

    #[test]
    fn test_bytes_to_chunks() {
        let chunks = bytes_to_chunks(&[0b01101100], 2);
        assert_eq!(chunks, vec![0b00, 0b11, 0b10, 0b01]);
    }

    #[test]
    fn test_full_byte() {
        let chunks = bytes_to_chunks(&[0b01101100, 0b10100110], 8);
        assert_eq!(chunks, vec![0b01101100, 0b10100110]);
    }
}
