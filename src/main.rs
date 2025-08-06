#![allow(unused)]

use code::Codeword;
use hash_chain::hash_chain;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

use crate::hash::Hash;

mod code;
mod hash;
mod hash_chain;

const MESSAGE_LEN: usize = 32;
const RAND_LEN: usize = 23;

#[derive(Clone)]
struct Rho(pub [u8; RAND_LEN]);
impl Rho {
    pub fn random(rng: &mut StdRng) -> Rho {
        let mut rho = Rho([0; RAND_LEN]);
        rng.fill_bytes(&mut rho.0);
        rho
    }
}

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

impl Param {
    pub fn random(param_len: usize, rng: &mut StdRng) -> Self {
        let mut data = Vec::new();
        data.resize(param_len, 0);
        rng.fill_bytes(&mut data);
        Self { data }
    }
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
    end_hashes: Vec<Hash>,
}

impl Pk {
    pub fn derive(sk: &Sk, chunk_bits: usize) -> Self {
        let param = sk.param.clone();
        let chain_len = 1 << chunk_bits;
        let end_hashes = sk
            .start_hashes
            .iter()
            .enumerate()
            .map(|(chain_index, start_hash)| {
                hash_chain(
                    &param,
                    chain_index,
                    *start_hash,
                    /* start pos */ 0,
                    chain_len - 1,
                )
            })
            .collect();
        Self { param, end_hashes }
    }
}

/// A secret key.
#[derive(Clone, Debug)]
struct Sk {
    param: Param,
    start_hashes: Vec<Hash>,
}

impl Sk {
    pub fn random(rng: &mut StdRng, param: Param, num_chains: usize) -> Self {
        let start_hashes = (0..num_chains).map(|_| Hash::random(rng)).collect();
        Self {
            param,
            start_hashes,
        }
    }
}

#[derive(Clone)]
struct Signature {
    rho: Rho,
    hashes: Vec<Hash>,
}

struct Signer {
    rng: StdRng,
    /// The number of times we try to grind the message.
    max_retries: usize,
    /// The number of bits per chunk.
    chunk_bits: usize,
    /// ???
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
            max_retries: 100_000,
            chunk_bits: chunk_size,
            num_chunks,
            param_len: 18,
            target_sum: 297,
            num_chains: num_chunks,
        }
    }
}

impl Signer {
    /// Generate a random key pair.
    pub fn gen_pair(&mut self) -> (Sk, Pk) {
        let param = Param::random(self.param_len, &mut self.rng);
        let sk = Sk::random(&mut self.rng, param.clone(), self.num_chains);
        let pk = Pk::derive(&sk, self.chunk_bits);
        (sk, pk)
    }

    pub fn sign(&mut self, sk: &Sk, message: &Message) -> Option<Signature> {
        let (codeword, rho) = code::grind(
            self.num_chains,
            self.chunk_bits,
            self.target_sum,
            self.max_retries,
            &sk.param,
            message,
            &mut self.rng,
        )?;
        assert_eq!(codeword.num_chunks(), self.num_chains);

        let start_hashes = sk.start_hashes.iter();
        let chunks = codeword.chunks().iter().map(|&chunk| chunk as usize);
        let hashes = start_hashes
            .zip(chunks)
            .enumerate()
            .map(|(chain_index, (start_hash, start_pos))| {
                hash_chain(&sk.param, chain_index, *start_hash, 0, start_pos)
            })
            .collect();

        Some(Signature { rho, hashes })
    }

    pub fn verify(&self, pk: &Pk, signature: &Signature, message: &Message) -> bool {
        let codeword = Codeword::new(
            self.num_chains,
            self.chunk_bits,
            &pk.param,
            message,
            &signature.rho,
        );
        if codeword.sum() != self.target_sum {
            return false;
        }
        assert_eq!(codeword.num_chunks(), self.num_chains);

        let chain_len = 1 << self.chunk_bits;
        let hashes = signature.hashes.iter();
        let chunks = codeword.chunks().iter().map(|&chunk| chunk as usize);
        let end_hashes = hashes
            .zip(chunks)
            .enumerate()
            .map(|(chain_index, (hash, hash_pos))| {
                hash_chain(
                    &pk.param,
                    chain_index,
                    *hash,
                    hash_pos,
                    chain_len - 1 - hash_pos,
                )
            });

        end_hashes.eq(pk.end_hashes.iter().cloned())
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
