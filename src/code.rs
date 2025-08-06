//! Encoding related stuff.

use bitvec::prelude::*;
use rand::rngs::StdRng;

use crate::{Message, Param, Rho, hash::tweak_hash_message, spec::Spec};

/// Find a suitable encoding to fit into the target sum.
pub fn grind(
    spec: &Spec,
    max_retries: usize,
    param: &Param,
    message: &Message,
    rng: &mut StdRng,
) -> Option<(Codeword, Rho)> {
    for _ in 0..max_retries {
        let rho = Rho::random(rng);
        match new_valid(spec, param, message, &rho) {
            Some(codeword) => return Some((codeword, rho)),
            None => continue,
        }
    }
    // give up because we couldn't find a valid encoding in a reasonable number of attempts.
    None
}

pub fn new_valid(spec: &Spec, param: &Param, message: &Message, rho: &Rho) -> Option<Codeword> {
    let codeword = Codeword::new(spec, param, message, rho);
    if codeword.sum() == spec.target_sum {
        Some(codeword)
    } else {
        None
    }
}

pub struct Codeword {
    chunks: Vec<u8>,
}

impl Codeword {
    pub fn new(spec: &Spec, param: &Param, message: &Message, rho: &Rho) -> Codeword {
        let full_hash = tweak_hash_message(param, message, rho);
        let trunc_hash = &full_hash.as_ref()[0..spec.num_chains * spec.chunk_bits / 8];
        let chunks = bytes_to_chunks(trunc_hash, spec.chunk_bits);
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
