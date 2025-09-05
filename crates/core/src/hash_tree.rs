use crate::{Hash, Param, hash::tweak_hash_tree_node};
use serde::{Deserialize, Serialize};

pub struct HashTree {
    /// The hash nodes in each level of the tree.
    ///
    /// - `levels[0]` contains all leaf nodes (bottom level)
    /// - `levels[levels.len() - 1]` contains the single root node (top level)
    ///
    /// Within each level, nodes are ordered left-to-right. For example,
    /// `levels[l][2i]` and `levels[l][2i + 1]` are hashed together to produce `levels[l + 1][i]`.
    pub levels: Vec<Vec<Hash>>,

    /// The root hash of the Hash tree.
    ///
    /// This is equal to `levels[levels.len() - 1][0]`.
    pub root: Hash,
}

impl HashTree {
    /// Constructs a new Hash tree from a vector of leaf nodes.
    ///
    /// It uses the hash crate::hash::tweak_hash_tree_node
    ///
    /// # Arguments
    ///
    /// * `param` - Cryptographic parameters for the hash function
    /// * `leaves` - Vector of leaf hashes (must be a power of 2 in length)
    ///
    /// # Returns
    ///
    /// A `HashTree` containing all intermediate nodes organized by level
    /// and the computed root hash.
    ///
    /// # Panics
    ///
    /// Panics if the number of leaves is not a power of 2.
    pub fn new(param: &Param, leaves: Vec<Hash>) -> Self {
        let num_leaves = leaves.len();
        assert!(
            num_leaves.is_power_of_two(),
            "Number of leaves must be a power of 2"
        );

        let height = num_leaves.ilog2() as usize;
        let mut levels = vec![leaves];

        for current_level_idx in 0..height {
            let parent_nodes = levels[current_level_idx]
                .chunks_exact(2)
                .enumerate()
                .map(|(i, pair)| {
                    tweak_hash_tree_node(
                        param,
                        &pair[0],
                        &pair[1],
                        current_level_idx as u32,
                        i as u32,
                    )
                })
                .collect();
            levels.push(parent_nodes);
        }

        let root = levels[height][0];

        Self { levels, root }
    }

    /// Generates a Hash proof for a leaf at the given index.
    ///
    /// The proof consists of sibling hashes at each level needed to reconstruct
    /// the path from the leaf to the root. When verifying, these siblings are
    /// hashed with intermediate values to recompute the root.
    ///
    /// # Arguments
    ///
    /// * `leaf_index` - The index of the leaf to prove
    ///
    /// # Returns
    ///
    /// A `HashTreeProof` containing:
    /// - The original leaf index
    /// - Authentication path: sibling hashes from leaf level to just below root
    pub fn get_proof(&self, leaf_index: usize) -> HashTreeProof {
        let mut path = Vec::new();
        let mut index = leaf_index;

        for level in &self.levels[..self.levels.len() - 1] {
            // Siblings appear in pairs at indices (2i, 2i + 1)
            // so we can find the index of a sibling by flipping
            // the least-significant bit.
            let sibling_index = index ^ 1;
            path.push(level[sibling_index]);
            // The parent index for siblings (2i, 2i + 1) is i
            index /= 2;
        }

        HashTreeProof { leaf_index, path }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashTreeProof {
    leaf_index: usize,
    pub path: Vec<Hash>,
}

impl HashTreeProof {
    /// Verifies that a leaf value belongs to a Hash tree with the given root.
    ///
    /// Reconstructs the path from leaf to root by iteratively hashing the
    /// current value with siblings from the path. The proof is valid if the
    /// computed root matches the expected root.
    ///
    /// # Arguments
    ///
    /// * `param` - Cryptographic parameters for the hash function
    /// * `leaf` - The leaf hash value to verify
    /// * `root` - The expected root hash of the Hash tree
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid (computed root matches expected root), `false` otherwise
    pub fn verify(&self, param: &Param, leaf: &Hash, root: &Hash) -> bool {
        let mut current_hash = *leaf;
        let mut index = self.leaf_index;

        for (level, &sibling_hash) in self.path.iter().enumerate() {
            // Siblings appear in pairs at indices (2i, 2i + 1)
            // So we can determine the order of siblings by comparing the
            // least significant bit
            let (left, right) = if index & 1 == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };

            // The parent index for siblings (2i, 2i + 1) is i
            let parent_index = index / 2;

            current_hash =
                tweak_hash_tree_node(param, &left, &right, level as u32, parent_index as u32);
            index = parent_index;
        }
        current_hash == *root
    }
}
