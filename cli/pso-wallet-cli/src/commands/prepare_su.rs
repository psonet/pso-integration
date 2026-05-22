//! `pso-wallet-cli prepare-su` — turn an SRA-delivered SU receipt into
//! a [`SuOwnershipWitness`] the wallet can later prove against.
//!
//! The wallet's `consent_sk` plus the receipt's `pk_cu` + `su_nonce`
//! reconstruct the same `shared_sk` the SRA used; the resulting
//! `derived_owner` should match the SU's on-chain `derivedOwner`.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use eyre::Result;
use k256::{PublicKey, SecretKey};
use pso_l2_client::wallet::prepare_su_ownership_material;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// On-chain SU id the SRA minted (`0x...`, 32-byte hex).
    #[arg(long)]
    pub su_id: String,
    /// SRA-supplied ephemeral public key `pk_cu` from the receipt
    /// (33-byte compressed SEC1 hex).
    #[arg(long)]
    pub pk_cu: String,
    /// 32-byte LE `su_nonce` extracted from the decrypted report.
    #[arg(long)]
    pub su_nonce: String,
    /// Output JSON path for the [`SuOwnershipWitness`] artifact.
    /// The wallet stores this and later passes it to `aggregate`.
    #[arg(long)]
    pub output: PathBuf,
}

pub fn run(consent_key: &[u8; 32], args: Args) -> Result<()> {
    let su_id = super::parse_uint256(&args.su_id)?;
    let consent_sk = SecretKey::from_slice(consent_key)?;

    let pk_cu_bytes = strip_hex(&args.pk_cu)?;
    let pk_cu = PublicKey::from_sec1_bytes(&pk_cu_bytes)
        .map_err(|e| eyre::eyre!("pk_cu not valid SEC1: {e}"))?;

    let nonce_bytes = strip_hex(&args.su_nonce)?;
    if nonce_bytes.len() != 32 {
        eyre::bail!("su_nonce must be 32 bytes, got {}", nonce_bytes.len());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);

    let witness = prepare_su_ownership_material(&consent_sk, &pk_cu, nonce, su_id)?;
    crate::write_json(&args.output, &witness)?;
    println!(
        "{{\"su_id\":\"{}\",\"derived_owner\":\"{}\"}}",
        witness.su_id, witness.derived_owner_be_hex
    );
    Ok(())
}

fn strip_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}
