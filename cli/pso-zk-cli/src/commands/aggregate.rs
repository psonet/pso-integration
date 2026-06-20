//! Handler for the `proof aggregate` CLI command.
//!
//! Flat-aggregation proving (the `AggregationTier` family in
//! `pso-zk-canonical`) is driven end-to-end by the wallet surface
//! (`pso-mobile-integration`'s `Wallet::prove_ownership`, exercised by
//! `pso-wallet-cli aggregate`), which owns the per-SU witness assembly.
//! This offline ZK CLI doesn't carry that witness-assembly path, so the
//! subcommand fails fast with a pointer to the supported route rather
//! than half-implementing a parallel one.

use std::path::Path;

use anyhow::{bail, Result};

/// Run the `proof aggregate` command end-to-end.
pub fn handle_proof_aggregate(input_path: &Path, output_path: &Path) -> Result<()> {
    let _ = (input_path, output_path);
    bail!(
        "proof aggregate is not available in pso-zk-cli: flat-aggregation proving runs \
         through the wallet surface (`pso-wallet-cli aggregate`, backed by \
         pso-mobile-integration's `Wallet::prove_ownership`), which owns the per-SU \
         witness assembly."
    );
}
