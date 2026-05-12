//! Helpers for the e2e tests — RPC URL discovery, key generation,
//! deterministic SU id rolling.
//!
//! See `tests/full_flow.rs` for the actual test.

use std::env;

use alloy::primitives::U256;
use rand::rngs::OsRng;
use rand::RngCore;

/// Environment variable the e2e tests read for the L2 RPC URL.
pub const PSO_L2_RPC_ENV: &str = "PSO_L2_RPC";

/// Hardhat default mnemonic account #0 — prefunded in pso-chain dev
/// genesis. Used as the SRA signer in tests (the SRA must be a
/// registered registrar with token balance to pay gas).
pub const ADMIN_SECRET_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

/// PSO devnet chain id.
pub const DEVNET_CHAIN_ID: u64 = 19_280_501;

/// Fetch the L2 RPC URL from `PSO_L2_RPC` or fall back to the devnet
/// default (`http://127.0.0.1:19545`).
pub fn rpc_url() -> String {
    env::var(PSO_L2_RPC_ENV).unwrap_or_else(|_| "http://127.0.0.1:19545".to_string())
}

/// Generate a fresh random 32-byte secp256k1 secret key.
pub fn random_secret_key() -> [u8; 32] {
    let mut sk = [0u8; 32];
    OsRng.fill_bytes(&mut sk);
    sk
}

/// Generate a fresh random uint256 id (for SU / SR / TD).
pub fn random_id() -> U256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    U256::from_be_bytes(bytes)
}
