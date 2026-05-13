//! Lazy-initialized circuit singletons.
//!
//! Circuit bytecodes are embedded at compile time via `include_str!()`.
//! Each circuit is initialized exactly once on first use via `OnceCell`.

use once_cell::sync::OnceCell;

use pso_zk_circuit_noir::{
    circuit_loader, CircuitBytecode, NoirCircuitConfig, NoirFullProofCircuit, NoirOwnershipCircuit,
    ZKCircuit, ZKMode,
};

use crate::types::MobileError;

// -- Standalone circuits -------------------------------------------------- //

const FULL_PROOF_JSON: &str =
    include_str!("../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/full_proof.json");
const OWNERSHIP_PROOF_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/ownership_proof.json"
);

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

const FLAT_AGG_N1_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/flat_aggregation_n1.json"
);
const FLAT_AGG_N2_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/flat_aggregation_n2.json"
);
const FLAT_AGG_N4_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/flat_aggregation_n4.json"
);
const FLAT_AGG_N8_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/flat_aggregation_n8.json"
);
const FLAT_AGG_N16_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/flat_aggregation_n16.json"
);
const FLAT_AGG_N32_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/flat_aggregation_n32.json"
);
const FLAT_AGG_N64_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/flat_aggregation_n64.json"
);

/// Load the bytecode for the chosen flat-aggregation tier.
pub fn flat_aggregation_bytecode(tier_n: u32) -> Result<CircuitBytecode, MobileError> {
    let json = match tier_n {
        1 => FLAT_AGG_N1_JSON,
        2 => FLAT_AGG_N2_JSON,
        4 => FLAT_AGG_N4_JSON,
        8 => FLAT_AGG_N8_JSON,
        16 => FLAT_AGG_N16_JSON,
        32 => FLAT_AGG_N32_JSON,
        64 => FLAT_AGG_N64_JSON,
        other => {
            return Err(MobileError::AggregationTierUnavailable {
                detail: format!("no flat-aggregation circuit for tier_n={other}"),
            })
        }
    };
    circuit_loader::load_circuit_from_str(json).map_err(|e| MobileError::CircuitInitFailed {
        detail: e.to_string(),
    })
}
