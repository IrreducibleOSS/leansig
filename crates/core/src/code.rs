// Copyright 2025 Irreducible Inc.
<<<<<<< HEAD
=======

>>>>>>> 14c2aa0 (add copyright)
//! Encoding related stuff.

use bitvec::prelude::*;
use rand::rngs::StdRng;

use crate::{Message, Nonce, Param, hash::tweak_hash_message, spec::Spec};

/// Try to find a suitable encoding to fit into the target sum.
///
/// For this we are going to try different random parameter values until we find a valid encoding.
/// It should not take too many iterations, but in case it does, we will give up and return `None`.
pub fn grind(
    spec: &Spec,
    max_retries: usize,
    param: &Param,
    message: &Message,
    rng: &mut StdRng,
) -> Option<(Codeword, Nonce)> {
    for _ in 0..max_retries {
        let rho = Nonce::random(rng);
        match new_valid(spec, param, message, &rho) {
            Some(codeword) => return Some((codeword, rho)),
            None => continue,
        }
    }
    // give up because we couldn't find a valid encoding in a reasonable number of attempts.
    None
}

/// Creates a new codeword and returns `Some` only if the codeword valid, that is, the sum
/// of chunks is equal to the target sum dictated by the spec.
pub fn new_valid(spec: &Spec, param: &Param, message: &Message, nonce: &Nonce) -> Option<Codeword> {
    let codeword = Codeword::new(spec, param, message, nonce);
    if codeword.sum() == spec.target_sum {
        Some(codeword)
    } else {
        None
    }
}

/// Codeword is basically a coordinate on this hypercube structure.
///
/// The origin of this structure is where the private key is stored.
pub struct Codeword {
    coords: Vec<u8>,
}

impl Codeword {
    pub fn new(spec: &Spec, param: &Param, message: &Message, nonce: &Nonce) -> Codeword {
        let full_hash = tweak_hash_message(param, message, nonce);
        let trunc_hash = &full_hash.as_ref()[0..spec.message_hash_len];
        let coords = bytes_to_coordinates(trunc_hash, spec.coordinate_resolution_bits);
        assert_eq!(coords.len(), spec.dimension());
        Self { coords }
    }

    /// Returns the sum over all the coordinates.
    ///
    /// You can think about it as a distance from the source, the where the secret key is stored.
    ///
    /// In our use case, this is the number of hashes required to get from the secret key to the
    /// message and for the efficiency of verifier we want to minimize this.
    pub fn sum(&self) -> usize {
        self.coords
            .iter()
            .map(|&coordinate| coordinate as usize)
            .sum()
    }

    pub fn dimension(&self) -> usize {
        self.coords.len()
    }

    pub fn coords(&self) -> &[u8] {
        &self.coords
    }
}

/// Chops bytes into coordinates of a given resolution.
fn bytes_to_coordinates(bytes: &[u8], resolution_bits: usize) -> Vec<u8> {
    assert!(resolution_bits <= 8);
    assert!(resolution_bits.is_power_of_two());
    bytes
        .view_bits::<Lsb0>()
        .chunks_exact(resolution_bits)
        .map(|coordinate| coordinate.load::<u8>())
        .collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use super::bytes_to_coordinates;

    #[test]
    fn test_bytes_to_coordinates() {
        let coords = bytes_to_coordinates(&[0b01101100], 2);
        assert_eq!(coords, vec![0b00, 0b11, 0b10, 0b01]);
    }

    #[test]
    fn test_full_byte() {
        let coords = bytes_to_coordinates(&[0b01101100, 0b10100110], 8);
        assert_eq!(coords, vec![0b01101100, 0b10100110]);
    }
}
