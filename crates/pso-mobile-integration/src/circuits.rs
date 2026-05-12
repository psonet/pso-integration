//! Lazy-initialized circuit singletons.
//!
//! Circuit bytecodes are embedded at compile time via `include_str!()`.
//! Each circuit is initialized exactly once on first use via `OnceLock`.

use once_cell::sync::OnceCell;

use pso_zk_circuit_noir::{
    circuit_loader, NoirCircuitConfig, NoirFullProofCircuit, NoirOwnershipCircuit,
    NoirSuOwnershipAggregationCircuit, ZKCircuit, ZKMode,
};

use crate::types::MobileError;

const FULL_PROOF_JSON: &str =
    include_str!("../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/full_proof.json");
const OWNERSHIP_PROOF_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/ownership_proof.json"
);

const AGGREGATION_N1_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n1.json"
);
const AGGREGATION_N2_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n2.json"
);
const AGGREGATION_N4_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n4.json"
);
const AGGREGATION_N6_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n6.json"
);
const AGGREGATION_N8_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n8.json"
);
const AGGREGATION_N16_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n16.json"
);
const AGGREGATION_N32_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n32.json"
);
const AGGREGATION_N64_JSON: &str = include_str!(
    "../../../../pso-zk-circuits/crates/pso-zk-circuit-noir/data/su_ownership_aggregation_n64.json"
);

static FULL_PROOF_CIRCUIT: OnceCell<NoirFullProofCircuit> = OnceCell::new();
static OWNERSHIP_CIRCUIT: OnceCell<NoirOwnershipCircuit> = OnceCell::new();

static AGGREGATION_N1: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGGREGATION_N2: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGGREGATION_N4: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGGREGATION_N6: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGGREGATION_N8: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGGREGATION_N16: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGGREGATION_N32: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();
static AGGREGATION_N64: OnceCell<NoirSuOwnershipAggregationCircuit> = OnceCell::new();

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

fn aggregation_circuit_init(
    json: &str,
    tier_n: u32,
    vk_bytes: &'static [u8],
) -> Result<NoirSuOwnershipAggregationCircuit, MobileError> {
    let bytecode = circuit_loader::load_circuit_from_str(json).map_err(|e| {
        MobileError::CircuitInitFailed {
            detail: e.to_string(),
        }
    })?;
    NoirSuOwnershipAggregationCircuit::new(bytecode.bytecode, tier_n, vk_bytes.to_vec()).map_err(
        |e| MobileError::CircuitInitFailed {
            detail: e.to_string(),
        },
    )
}

/// Get or initialize the SU-ownership aggregation circuit for tier
/// `tier_n`. Returns an error if `tier_n` isn't one of the supported
/// tier sizes (1, 2, 4, 6, 8, 16, 32, 64).
pub fn su_aggregation_circuit(
    tier_n: u32,
) -> Result<&'static NoirSuOwnershipAggregationCircuit, MobileError> {
    use pso_zk_canonical as zk;
    match tier_n {
        1 => AGGREGATION_N1.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N1_JSON,
                1,
                zk::SU_OWNERSHIP_AGGREGATION_N1.vk_bytes,
            )
        }),
        2 => AGGREGATION_N2.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N2_JSON,
                2,
                zk::SU_OWNERSHIP_AGGREGATION_N2.vk_bytes,
            )
        }),
        4 => AGGREGATION_N4.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N4_JSON,
                4,
                zk::SU_OWNERSHIP_AGGREGATION_N4.vk_bytes,
            )
        }),
        6 => AGGREGATION_N6.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N6_JSON,
                6,
                zk::SU_OWNERSHIP_AGGREGATION_N6.vk_bytes,
            )
        }),
        8 => AGGREGATION_N8.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N8_JSON,
                8,
                zk::SU_OWNERSHIP_AGGREGATION_N8.vk_bytes,
            )
        }),
        16 => AGGREGATION_N16.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N16_JSON,
                16,
                zk::SU_OWNERSHIP_AGGREGATION_N16.vk_bytes,
            )
        }),
        32 => AGGREGATION_N32.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N32_JSON,
                32,
                zk::SU_OWNERSHIP_AGGREGATION_N32.vk_bytes,
            )
        }),
        64 => AGGREGATION_N64.get_or_try_init(|| {
            aggregation_circuit_init(
                AGGREGATION_N64_JSON,
                64,
                zk::SU_OWNERSHIP_AGGREGATION_N64.vk_bytes,
            )
        }),
        _ => Err(MobileError::AggregationTierUnavailable {
            detail: format!("no aggregation circuit for tier_n={tier_n}"),
        }),
    }
}
