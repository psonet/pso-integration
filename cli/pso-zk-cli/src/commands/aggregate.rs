//! Handler for the `proof aggregate` CLI command.
//!
//! Builds an aggregation proof for TributeDraft submission.
//!
//! The flat aggregation-witness API the previous version of this
//! handler used has been replaced by a recursive-aggregation circuit
//! family in pso-zk-circuits. The Rust wrapper around the
//! `pso-recursive-aggregation-circuit-n*` family
//! (`NoirRecursiveAggregationCircuit`) is still pending; see
//! `crates/pso-zk-circuit-noir/src/lib.rs` "Recursive aggregation
//! circuit (pending)" and `docs/aggregation-redesign.md`. Until the
//! wrapper lands, this handler always fails fast with a clear error.

use std::path::Path;

use anyhow::{bail, Result};

/// Run the `proof aggregate` command end-to-end.
pub fn handle_proof_aggregate(input_path: &Path, output_path: &Path) -> Result<()> {
    let _ = (input_path, output_path);
    bail!(
        "proof aggregate is temporarily disabled: the recursive-aggregation circuit wrapper \
         (NoirRecursiveAggregationCircuit) is pending in pso-zk-circuits. See \
         docs/aggregation-redesign.md."
    );
}
