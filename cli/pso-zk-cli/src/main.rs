//! PSO ZK Proof CLI entry point.
//!
//! Commands:
//!
//! ```text
//! pso-zk-cli nft generate --type tribute-draft -o output.json
//! pso-zk-cli proof generate --nft output.json --circuit full_proof.json -o proof.json
//! pso-zk-cli proof verify --proof proof.json --circuit full_proof.json
//! pso-zk-cli proof aggregate --input aggregation_input.json -o proof.json
//! ```

use clap::Parser;

use pso_zk_cli::commands::{aggregate, nft, proof};
use pso_zk_cli::{Cli, Commands, NftCommands, ProofCommands};

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Nft { action } => match action {
            NftCommands::Generate { nft_type, output } => {
                nft::handle_nft_generate(nft_type, &output)
            }
        },
        Commands::Proof { action } => match action {
            ProofCommands::Generate {
                nft,
                circuit,
                mode,
                output,
                redeemer,
                chain_id,
            } => decode_redeemer(&redeemer).and_then(|r| {
                proof::handle_proof_generate(&nft, &circuit, mode, &output, &r, chain_id)
            }),
            ProofCommands::Verify { proof, circuit } => {
                proof::handle_proof_verify(&proof, &circuit)
            }
            ProofCommands::Aggregate { input, output } => {
                aggregate::handle_proof_aggregate(&input, &output)
            }
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

/// Decode a `0x`-prefixed (or bare) 20-byte hex address for the redemption
/// `binding_hash`.
fn decode_redeemer(s: &str) -> anyhow::Result<[u8; 20]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("redeemer hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("redeemer must be 20 bytes"))
}
