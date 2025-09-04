use hash_chain::hash_chain;
use rand::{RngCore, rngs::StdRng};
use serde::{Deserialize, Serialize};
use spec::Spec;

use crate::hash::Hash;
use crate::hash::tweak_public_key_hash;
use crate::hash_tree::{HashTree, HashTreeProof};

pub mod code;
pub mod hash;
pub mod hash_chain;
pub mod hash_tree;

pub mod spec;

const MESSAGE_LEN: usize = 32;
const RAND_LEN: usize = 23;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nonce(pub [u8; RAND_LEN]);

impl Nonce {
    /// Generate a random nonce.
    pub fn random(rng: &mut StdRng) -> Nonce {
        let mut nonce = Nonce([0; RAND_LEN]);
        rng.fill_bytes(&mut nonce.0);
        nonce
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Message(pub [u8; MESSAGE_LEN]);

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Param {
    data: Vec<u8>,
}

impl Param {
    pub fn random(param_len: usize, rng: &mut StdRng) -> Self {
        let mut data = vec![0; param_len];
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pk {
    pub param: Param,
    pub end_hashes: Vec<Hash>,
}

impl Pk {
    pub fn derive(sk: &Sk, spec: &Spec) -> Self {
        let param = sk.param.clone();
        let chain_len = spec.chain_len();
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sk {
    param: Param,
    start_hashes: Vec<Hash>,
}

impl Sk {
    pub fn random(rng: &mut StdRng, param: Param, spec: &Spec) -> Self {
        let start_hashes = (0..spec.dimension()).map(|_| Hash::random(rng)).collect();
        Self {
            param,
            start_hashes,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtsSignature {
    pub nonce: Nonce,
    pub hashes: Vec<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The one-time signature
    pub signature: OtsSignature,
    /// Proof that the public-key associated to the epoch is present in the XMSS
    /// hash tree
    pub hash_tree_proof: HashTreeProof,
    /// The public key used for this signature
    pub public_key: Pk,
}

pub struct Signer {
    rng: StdRng,
    max_retries: usize,
    /// The specification defining the signature scheme parameters (chain length, dimensions, etc.)
    pub spec: Spec,
    /// The public parameter shared across all signatures from this signer
    pub param: Param,
    hash_tree: HashTree,
    key_pairs: Vec<(Sk, Pk)>,
    /// The root hash of the XMSS Merkle tree, serving as the public commitment to all one-time keys
    pub root: Hash,
}

impl Signer {
    /// Create a new XMSS signer with multiple one-time key pairs
    ///
    /// # Arguments
    /// * `rng` - Random number generator for key generation
    /// * `max_retries` - Maximum attempts to find a valid signature (for grinding the nonce)
    /// * `spec` - The specification defining the signature scheme parameters
    /// * `lifetime` - Number of one-time signatures this signer can produce (number of epochs)
    ///
    /// # Returns
    /// A new `Signer` with `lifetime` key pairs and a Merkle tree commitment
    pub fn new(mut rng: StdRng, max_retries: usize, spec: Spec, lifetime: usize) -> Self {
        let param = Param::random(spec.param_len, &mut rng);

        let mut key_pairs = Vec::new();
        for _ in 0..lifetime {
            let sk = Sk::random(&mut rng, param.clone(), &spec);
            let pk = Pk::derive(&sk, &spec);
            key_pairs.push((sk, pk));
        }

        let pub_key_hashes: Vec<_> = key_pairs
            .iter()
            .map(|(_, pk)| tweak_public_key_hash(&param, pk))
            .collect();

        let hash_tree = HashTree::new(&param, pub_key_hashes);
        let root = hash_tree.root.clone();

        Self {
            rng,
            max_retries,
            spec,
            hash_tree,
            key_pairs,
            param,
            root,
        }
    }

    /// Sign a message using the key at the given epoch
    ///
    /// Returns None if the signer could not produce a Signature
    pub fn sign(&mut self, epoch: usize, message: &Message) -> Option<Signature> {
        assert!(
            epoch < self.key_pairs.len(),
            "epoch must be less than the total number of keys"
        );
        let (sk, pk) = &self.key_pairs[epoch];

        let (codeword, nonce) = code::grind(
            &self.spec,
            self.max_retries,
            &sk.param,
            message,
            &mut self.rng,
        )?;
        assert_eq!(codeword.dimension(), self.spec.dimension());

        let start_hashes = sk.start_hashes.iter();
        let coords = codeword.coords().iter().map(|&coords| coords as usize);
        let hashes = start_hashes
            .zip(coords)
            .enumerate()
            .map(|(chain_index, (start_hash, start_pos))| {
                hash_chain(&sk.param, chain_index, *start_hash, 0, start_pos)
            })
            .collect();

        let signature = OtsSignature { nonce, hashes };
        let hash_tree_proof = self.hash_tree.get_proof(epoch);
        let public_key = pk.clone();

        Some(Signature {
            signature,
            hash_tree_proof,
            public_key,
        })
    }
}

/// Verify an XMSS signature with HashTree proof
///
/// The verification procedure consists of two main steps:
///
/// 1. **One-Time Signature (OTS) Verification**:
///    - Reconstruct the codeword from the message and nonce
///    - Use the codeword coordinates to determine positions in hash chains
///    - Complete the hash chains from the provided intermediate hashes
///    - Compare the computed end hashes with the public key's end hashes
///
/// 2. **Merkle Tree Proof Verification**:
///    - Hash the public key to get the leaf value
///    - Verify the proof path from leaf to the committed root
///    - Ensure the public key is indeed part of the XMSS tree
///
/// # Arguments
/// * `spec` - The specification for the signature scheme
/// * `param` - The parameter used by the signer
/// * `message` - The message that was signed
/// * `signature` - The XMSS signature with hash tree proof and public key
/// * `root` - The root hash of the XMSS tree to verify against
///
/// # Returns
/// `true` if both the OTS signature and tree proof are valid, `false` otherwise
pub fn verify_signature(
    spec: &Spec,
    param: &Param,
    message: &Message,
    signature: &Signature,
    root: &Hash,
) -> bool {
    // Use the public key from the signature for verification
    let pk = &signature.public_key;

    // Step 1: Verify the one-time signature
    // First, reconstruct the codeword from the message and nonce
    let Some(codeword) = code::new_valid(spec, &pk.param, message, &signature.signature.nonce)
    else {
        // The message + nonce combination doesn't produce a valid codeword
        // This means the signature is invalid
        return false;
    };
    assert_eq!(codeword.dimension(), spec.dimension());

    // The codeword tells us positions in each hash chain
    // We need to complete the hash chains from those positions to the end
    let chain_len = spec.chain_len();
    let hashes = signature.signature.hashes.iter();
    let coords = codeword.coords().iter().map(|&coord| coord as usize);

    // For each chain, compute from the given hash at position `hash_pos`
    // to the end of the chain (position chain_len - 1)
    let end_hashes = hashes
        .zip(coords)
        .enumerate()
        .map(|(chain_index, (hash, hash_pos))| {
            hash_chain(
                &pk.param,
                chain_index,
                *hash,
                hash_pos,                 // Current position in chain
                chain_len - 1 - hash_pos, // Steps remaining to end
            )
        });

    // Compare computed end hashes with the public key's end hashes
    // If they don't match, the OTS signature is invalid
    if !end_hashes.eq(pk.end_hashes.iter().cloned()) {
        return false;
    }

    // Step 2: Verify the Merkle tree proof
    // This proves that the public key used above is part of the XMSS tree
    let leaf_hash = tweak_public_key_hash(param, pk);
    signature.hash_tree_proof.verify(param, &leaf_hash, root)
}

/// A signature from a single validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// The epoch used for signing
    pub epoch: usize,
    /// The XMSS signature
    pub signature: Signature,
    /// The root hash this signature should verify against
    pub xmss_root: Hash,
    /// The parameter used by this validator
    pub param: Param,
}

/// Aggregated signatures from multiple validators
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedSignature {
    /// Individual signatures from each validator
    pub signatures: Vec<ValidatorSignature>,
}

impl AggregatedSignature {
    /// Create a new aggregated signature from a list of validator signatures
    pub fn new(signatures: Vec<ValidatorSignature>) -> Self {
        Self { signatures }
    }
}

/// A collection of validator root hashes for verification
#[derive(Clone, Debug)]
pub struct AggregatedVerifier {
    /// List of registered validator roots
    roots: Vec<Hash>,
    /// The specification for the signature scheme
    spec: Spec,
}

impl AggregatedVerifier {
    /// Create a new validator roots collection with specification
    pub fn new(roots: Vec<Hash>, spec: Spec) -> Self {
        Self { roots, spec }
    }

    /// Verify an aggregated signature from multiple validators
    ///
    /// Returns `true` if all signatures are valid and from registered validators,
    /// `false` otherwise
    pub fn verify(&self, message: &Message, aggregated: &AggregatedSignature) -> bool {
        aggregated.signatures.iter().all(|sig| {
            // Check if this signature's root is in our validator set
            self.roots.contains(&sig.xmss_root) &&
                // Verify using the param from the ValidatorSignature
                verify_signature(
                    &self.spec,
                    &sig.param,
                    message,
                    &sig.signature,
                    &sig.xmss_root,
                )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_xmss_verify() {
        let spec = spec::SPEC_2;
        let mut signer = Signer::new(StdRng::seed_from_u64(0), 1000000, spec.clone(), 8);

        // Get public verification parameters
        let root = signer.root.clone();
        let param = signer.param.clone();

        let message1 = Message([10; 32]);
        let message2 = Message([20; 32]);
        let bad_message = Message([30; 32]);

        let sig1 = signer
            .sign(0, &message1)
            .expect("Failed to sign with epoch 0");
        let sig3 = signer
            .sign(3, &message2)
            .expect("Failed to sign with epoch 3");

        assert!(verify_signature(&spec, &param, &message1, &sig1, &root));
        assert!(verify_signature(&spec, &param, &message2, &sig3, &root));

        assert!(!verify_signature(&spec, &param, &bad_message, &sig1, &root));
        assert!(!verify_signature(&spec, &param, &message2, &sig1, &root));
        assert!(!verify_signature(&spec, &param, &message1, &sig3, &root));
    }

    #[test]
    fn test_aggregated_signatures() {
        let spec = spec::SPEC_2;

        // Create multiple validators (each with their own param)
        let mut validator1 = Signer::new(StdRng::seed_from_u64(1), 10000, spec.clone(), 4);
        let mut validator2 = Signer::new(StdRng::seed_from_u64(2), 10000, spec.clone(), 4);
        let mut validator3 = Signer::new(StdRng::seed_from_u64(3), 10000, spec.clone(), 4);

        // Register validator roots
        let roots = vec![
            validator1.root.clone(),
            validator2.root.clone(),
            validator3.root.clone(),
        ];

        // Create the validator roots collection for verification
        let verifier = AggregatedVerifier::new(roots.clone(), spec.clone());

        // Message to be signed by all validators
        let message = Message([42; 32]);

        // Each validator signs the message
        let sig1 = validator1.sign(0, &message).expect("Failed to sign");
        let sig2 = validator2.sign(0, &message).expect("Failed to sign");
        let sig3 = validator3.sign(0, &message).expect("Failed to sign");

        // Create aggregated signature
        let aggregated = AggregatedSignature::new(vec![
            ValidatorSignature {
                epoch: 0,
                signature: sig1,
                xmss_root: validator1.root.clone(),
                param: validator1.param.clone(),
            },
            ValidatorSignature {
                epoch: 0,
                signature: sig2,
                xmss_root: validator2.root.clone(),
                param: validator2.param.clone(),
            },
            ValidatorSignature {
                epoch: 0,
                signature: sig3,
                xmss_root: validator3.root.clone(),
                param: validator3.param.clone(),
            },
        ]);

        // Verify the aggregated signature (all should be valid)
        assert!(verifier.verify(&message, &aggregated));

        // Test with only 2 signatures
        let partial_aggregated = AggregatedSignature::new(vec![
            ValidatorSignature {
                epoch: 0,
                signature: validator1.sign(1, &message).expect("Failed to sign"),
                xmss_root: validator1.root.clone(),
                param: validator1.param.clone(),
            },
            ValidatorSignature {
                epoch: 0,
                signature: validator2.sign(1, &message).expect("Failed to sign"),
                xmss_root: validator2.root.clone(),
                param: validator2.param.clone(),
            },
        ]);

        // Both signatures should be valid
        assert!(verifier.verify(&message, &partial_aggregated));

        // Test with invalid signature
        let bad_message = Message([99; 32]);
        let bad_sig = validator1.sign(2, &bad_message).expect("Failed to sign");
        let invalid_aggregated = AggregatedSignature::new(vec![ValidatorSignature {
            epoch: 2,
            signature: bad_sig,
            xmss_root: validator1.root.clone(),
            param: validator1.param.clone(),
        }]);

        // Should fail because signature is for wrong message
        assert!(!verifier.verify(&message, &invalid_aggregated));
    }
}
