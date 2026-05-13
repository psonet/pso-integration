//! Lazy-initialized circuit singletons.
//!
//! Circuit bytecodes are embedded at compile time via `include_str!()`.
//! Each circuit is initialized exactly once on first use via `OnceCell`.

use once_cell::sync::OnceCell;

use pso_zk_circuit_noir::{
    circuit_loader, CircuitBytecode, NoirCircuitConfig, NoirFullProofCircuit, NoirOwnershipCircuit,
    ZKCircuit, ZKMode, FULL_PROOF_JSON, OWNERSHIP_PROOF_JSON,
};

use crate::types::MobileError;

// -- Standalone circuits -------------------------------------------------- //
//
// Bytecodes ride along with the cargo-fetched
// `pso-zk-circuit-noir` source via `pub const ..._JSON: &str`
// constants. We previously `include_str!`d a sibling-checkout
// relative path (`../../../../pso-zk-circuits/...`); that only
// resolves in the local multi-repo layout and breaks every single
// CI that clones one repo at a time.

static FULL_PROOF_CIRCUIT: OnceCell<NoirFullProofCircuit> = OnceCell::new();
static OWNERSHIP_CIRCUIT: OnceCell<NoirOwnershipCircuit> = OnceCell::new();

/// Get or initialize the full proof circuit (ownership + Merkle inclusion).
pub fn full_proof_circuit() -> Result<&'static NoirFullProofCircuit, MobileError> {
    FULL_PROOF_CIRCUIT.get_or_try_init(|| {
        let bytecode = circuit_loader::load_circuit_from_str(FULL_PROOF_JSON).map_err(|e| {
            MobileError::CircuitInitFailed {
                detail: e.to_string(),
            }
        })?;
        let config = NoirCircuitConfig {
            circuit: bytecode,
            version: "0.0.1",
            low_memory: true,
            scheme: ZKMode::UltraHonkKeccak,
        };
        NoirFullProofCircuit::setup(config).map_err(|e| MobileError::CircuitInitFailed {
            detail: e.to_string(),
        })
    })
}

/// Get or initialize the ownership-only circuit.
pub fn ownership_circuit() -> Result<&'static NoirOwnershipCircuit, MobileError> {
    OWNERSHIP_CIRCUIT.get_or_try_init(|| {
        let bytecode =
            circuit_loader::load_circuit_from_str(OWNERSHIP_PROOF_JSON).map_err(|e| {
                MobileError::CircuitInitFailed {
                    detail: e.to_string(),
                }
            })?;
        let config = NoirCircuitConfig {
            circuit: bytecode,
            version: "0.0.1",
            low_memory: true,
            scheme: ZKMode::UltraHonkKeccak,
        };
        NoirOwnershipCircuit::setup(config).map_err(|e| MobileError::CircuitInitFailed {
            detail: e.to_string(),
        })
    })
}

// -- Flat aggregation tier circuits --------------------------------------- //
//
// One bytecode JSON per canonical tier. The mobile prover doesn't wrap
// these in a `NoirCircuit` trait impl -- the witness shape varies per
// `N`, so the caller in `api.rs::prove_su_ownership_aggregation`
// builds the witness via
// `pso_integrations_shared::witness::build_flat_aggregation_witness`
// and calls `noir_rs::prove_ultra_honk_keccak` directly with the
// canonical VK bytes from `pso_zk_canonical::FLAT_AGGREGATION_N{N}`.

/// Load the bytecode for the chosen flat-aggregation tier.
///
/// JSON documents are sourced from `pso_zk_circuit_noir::
/// flat_aggregation_json(tier_n)` — the API mirrors
/// `SU_AGGREGATION_TIERS` and returns `None` for any tier outside
/// `{1, 2, 4, 8, 16, 32, 64}`.
pub fn flat_aggregation_bytecode(tier_n: u32) -> Result<CircuitBytecode, MobileError> {
    let json = pso_zk_circuit_noir::flat_aggregation_json(tier_n).ok_or_else(|| {
        MobileError::AggregationTierUnavailable {
            detail: format!("no flat-aggregation circuit for tier_n={tier_n}"),
        }
    })?;
    circuit_loader::load_circuit_from_str(json).map_err(|e| MobileError::CircuitInitFailed {
        detail: e.to_string(),
    })
}
