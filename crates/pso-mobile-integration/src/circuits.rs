//! Lazy-initialized circuit singletons.
//!
//! Circuit bytecodes are embedded at compile time via `include_str!()`.
//! Each circuit is initialized exactly once on first use via `OnceLock`.

use once_cell::sync::OnceCell;

use pso_zk_circuit_noir::{
    circuit_loader, NoirCircuitConfig, NoirFullProofCircuit, NoirOwnershipCircuit, ZKCircuit,
    ZKMode,
};

use crate::types::MobileError;

const FULL_PROOF_JSON: &str =
    include_str!("../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/full_proof.json");
const OWNERSHIP_PROOF_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/ownership_proof.json"
);

// Recursive aggregation circuits live in pso-zk-circuits as
// pso-recursive-aggregation-circuit-n{1,2,4,6,8,16,32,64}. The Rust
// wrapper (NoirRecursiveAggregationCircuit) is still pending — see
// `crates/pso-zk-circuit-noir/src/lib.rs` "Recursive aggregation
// circuit (pending)" and `docs/aggregation-redesign.md` in this
// repo. Until the wrapper lands, `aggregation_circuit` returns
// `AggregationTierUnavailable` for any tier.

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

/// Recursive aggregation circuits are pending — the Rust wrapper for
/// the `pso-recursive-aggregation-circuit-n*` family lands once
/// `xtask regenerate-canonical` has compiled the tier circuits and the
/// `NoirRecursiveAggregationCircuit` is added to pso-zk-circuit-noir.
/// Until then this returns `AggregationTierUnavailable` for every
/// tier. See `docs/aggregation-redesign.md`.
#[allow(dead_code)] // wired back up by the recursive-aggregation work
pub fn su_aggregation_circuit(tier_n: u32) -> Result<NoirFullProofCircuit, MobileError> {
    let _ = tier_n;
    Err(MobileError::AggregationTierUnavailable {
        detail: "recursive aggregation wrapper pending (NoirRecursiveAggregationCircuit not yet implemented in pso-zk-circuits)".to_string(),
    })
}
