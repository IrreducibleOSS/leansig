//! SP1-optimized Keccak256 implementation using the keccak_permute precompile.
//!
//! This module provides a Keccak256 hasher that uses SP1's syscall_keccak_permute
//! when running in the SP1 zkVM, significantly reducing cycles for keccak operations.

use tiny_keccak::Hasher;

/// SP1-optimized Keccak256 hasher
pub struct Keccak256 {
    state: [u64; 25],
    buf: Vec<u8>,
    offset: usize,
}

impl Keccak256 {
    const RATE: usize = 136; // Keccak256 rate in bytes (1088 bits)

    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buf: Vec::new(),
            offset: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Pad the message according to Keccak padding rules
        self.buf.push(0x01);
        while (self.buf.len() % Self::RATE) != (Self::RATE - 1) {
            self.buf.push(0x00);
        }
        self.buf.push(0x80);

        // Process all blocks
        for chunk in self.buf.chunks_exact(Self::RATE) {
            // XOR the chunk into the state
            for (i, byte) in chunk.iter().enumerate() {
                let state_word = i / 8;
                let byte_in_word = i % 8;
                self.state[state_word] ^= (*byte as u64) << (byte_in_word * 8);
            }

            // Apply the keccak permutation
            #[cfg(all(target_os = "zkvm", feature = "sp1"))]
            {
                extern "C" {
                    fn syscall_keccak_permute(state: *mut u64);
                }
                unsafe {
                    syscall_keccak_permute(self.state.as_mut_ptr());
                }
            }

            #[cfg(not(all(target_os = "zkvm", feature = "sp1")))]
            {
                // Fallback to software implementation when not in SP1 zkVM
                keccak_permute_software(&mut self.state);
            }
        }

        // Extract the hash (first 32 bytes of state)
        let mut output = [0u8; 32];
        for i in 0..4 {
            let bytes = self.state[i].to_le_bytes();
            output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        output
    }
}

/// Software implementation of keccak permutation for non-zkVM environments
#[cfg(not(all(target_os = "zkvm", feature = "sp1")))]
fn keccak_permute_software(state: &mut [u64; 25]) {
    // Use tiny-keccak's implementation as fallback
    use tiny_keccak::keccakf;
    keccakf(state);
}

/// Create a SP1-optimized Keccak256 hasher when sp1 feature is enabled
#[cfg(feature = "sp1")]
pub fn v256() -> Keccak256 {
    Keccak256::new()
}

/// Fallback to tiny-keccak when sp1 feature is not enabled
#[cfg(not(feature = "sp1"))]
pub fn v256() -> tiny_keccak::Keccak {
    tiny_keccak::Keccak::v256()
}