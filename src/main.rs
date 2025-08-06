#![allow(unused)]

use rand::{Rng, SeedableRng, rngs::StdRng};

mod code;
mod hash;
mod hash_chain;

const MESSAGE_LEN: usize = 32;
const RAND_LEN: usize = 23;

#[derive(Clone)]
struct Rho(pub [u8; RAND_LEN]);
struct Message(pub [u8; MESSAGE_LEN]);

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug)]
struct Param {
    data: Vec<u8>,
}

impl AsRef<[u8]> for Param {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// A public key.
#[derive(Clone, Debug)]
struct Pk {
    param: Param,
}

/// A secret key.
#[derive(Clone, Debug)]
struct Sk {
    param: Param,
}

#[derive(Clone)]
struct Signature {
    // TODO:
    rho: Rho,
}

struct Signer {
    rng: StdRng,
    /// The number of bits per chunk.
    chunk_size: usize,
    ///
    num_chunks: usize,
    /// The length of the parameter for hashing.
    param_len: usize,
    /// The number of chains.
    num_chains: usize,
    /// The sum of all coordinates of a vertex of a signature that we accept.
    target_sum: usize,
}

impl Default for Signer {
    fn default() -> Self {
        let message_hash_len = 18;
        let chunk_size = 4;
        let num_chunks = message_hash_len * 8 / chunk_size;
        Self {
            rng: StdRng::from_seed([0u8; 32]),
            chunk_size,
            num_chunks,
            param_len: 18,
            target_sum: 297,
            num_chains: todo!(),
        }
    }
}

impl Signer {
    /// Generate a random key pair.
    pub fn gen_pair(&mut self) -> (Sk, Pk) {
        // TODO: how do they run a chain hash?
        todo!()
    }

    pub fn sign(&mut self, sk: &Sk, message: &Message) -> Option<Signature> {
        todo!()
    }

    pub fn verify(&self, pk: &Pk, signature: &Signature, message: &Message) -> bool {
        todo!()
    }
}

fn main() {
    let mut signer = Signer::default();
    let (mut sk, mut pk) = signer.gen_pair();
    let message = Message([1; 32]);
    let signature = signer.sign(&sk, &message).unwrap();
    assert!(signer.verify(&pk, &signature, &message));
    ()
}
