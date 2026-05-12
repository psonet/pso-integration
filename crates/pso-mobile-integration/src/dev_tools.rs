//! Development-only utilities gated behind the `dev-tools` Cargo feature.
//!
//! These functions are compiled out of production builds entirely.

use rand::rngs::OsRng;

use crate::types::MerklePathElementInput;

/// Generate a random Merkle path for testing purposes.
///
/// Returns a path with 4–8 random elements. **Not suitable for production use.**
#[uniffi::export]
pub fn generate_random_merkle_path() -> Vec<MerklePathElementInput> {
    let mut rng = OsRng;
    let path = pso_nft::generate_test_merkle_path(&mut rng);

    path.into_iter()
        .map(|e| MerklePathElementInput {
            node_hash: e.node_hash.to_vec(),
            index: e.index as u8,
        })
        .collect()
}
