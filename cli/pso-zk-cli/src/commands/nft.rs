//! Handler for the `nft generate` CLI command.
//!
//! Generates a random NFT (TributeDraft or SpendingUnit) with an
//! associated PsoV1 signing keypair + nonce, computes its
//! `derivedOwner` and entity hash, and writes the result (including the
//! secret key) to a JSON file.
//!
//! NOTE: the pre-0.8 CLI relied on `pso-nft`'s `Generated` reference
//! generator. That crate is gone; the random NFT shapes are built
//! inline here from the `pso-chain-abi` entities + the `pso-protocol`
//! key/owner/hash formulas.

use std::path::Path;

use anyhow::{Context, Result};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use rand::rngs::OsRng;
use rand::RngCore;

use alloy_primitives::{Address, B256, U16, U64};
use pso_chain_abi::entity::{SpendingUnit, TributeDraft};
use pso_protocol::primitive::signature::SignatureScheme;
use pso_protocol::protocol::entity::Entity;
use pso_protocol::{Codec, PsoV1, Suite};

use crate::display::{build_table, KeyValueRow};
use crate::types::{GeneratedOutput, SpendingUnitJson, TributeDraftJson};
use crate::NftType;

type Fr = <PsoV1 as Suite>::Field;

/// Handle the `nft generate` command. Writes the NFT (with secret key +
/// nonce) to `output` as pretty-printed JSON, sets 0600 perms on Unix,
/// and prints a summary table.
pub fn handle_nft_generate(nft_type: NftType, output: &Path) -> Result<()> {
    // Deterministic-from-entropy RNG for the field/curve math.
    let mut os = OsRng;
    let mut seed = [0u8; 32];
    os.fill_bytes(&mut seed);
    let mut rng = StdRng::from_seed(seed);

    // NFT signing keypair + ownership nonce.
    let (sk, pk) = <PsoV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let derived_owner = PsoV1::derive_owner(&pk, nonce).context("derive_owner")?;
    let owner_b256 = B256::from_slice(&PsoV1::field_to_be_bytes(&derived_owner));

    let nft_id = field_b256(&mut rng);

    let (generated_output, table_rows) = match nft_type {
        NftType::SpendingUnit => {
            let entity = SpendingUnit {
                id: nft_id,
                derived_owner: owner_b256,
                attester: rand_address(&mut os),
                referrer: Address::ZERO,
                worldwide_day: U64::from(20_250_101u64),
                currency: U16::from(978u16),
                base: U64::from(100u64),
                atto: U64::from(0u64),
                sr: vec![field_b256(&mut rng)],
                ar: vec![],
            };
            let nft_hash = Entity::<PsoV1>::entity_hash(&entity).context("entity_hash")?;
            let json = SpendingUnitJson {
                id: hex_b256(&entity.id),
                derived_owner: hex_b256(&entity.derived_owner),
                attester: format!("0x{}", hex::encode(entity.attester)),
                referrer: format!("0x{}", hex::encode(entity.referrer)),
                worldwide_day: entity.worldwide_day.to::<u64>(),
                currency: entity.currency.to::<u16>(),
                base: entity.base.to::<u64>(),
                atto: entity.atto.to::<u64>(),
                sr: entity.sr.iter().map(hex_b256).collect(),
                ar: entity.ar.iter().map(hex_b256).collect(),
            };
            let out = build_output(
                "spending-unit",
                Some(json),
                None,
                &entity.id,
                &owner_b256,
                &nft_hash,
                &sk,
                nonce,
            )?;
            let rows = vec![
                row("NFT Type", "spending-unit"),
                row("ID", &hex_b256(&entity.id)),
                row("Derived Owner", &out.derived_owner),
                row("Currency", "978"),
            ];
            (out, rows)
        }
        NftType::TributeDraft => {
            let entity = TributeDraft {
                id: nft_id,
                derived_owner: owner_b256,
                worldwide_day: U64::from(20_250_101u64),
                currency: U16::from(978u16),
                base: U64::from(250u64),
                atto: U64::from(0u64),
                su_ids: vec![field_b256(&mut rng)],
            };
            let nft_hash = Entity::<PsoV1>::entity_hash(&entity).context("entity_hash")?;
            let json = TributeDraftJson {
                id: hex_b256(&entity.id),
                derived_owner: hex_b256(&entity.derived_owner),
                worldwide_day: entity.worldwide_day.to::<u64>(),
                currency: entity.currency.to::<u16>(),
                base: entity.base.to::<u64>(),
                atto: entity.atto.to::<u64>(),
                su_ids: entity.su_ids.iter().map(hex_b256).collect(),
            };
            let out = build_output(
                "tribute-draft",
                None,
                Some(json),
                &entity.id,
                &owner_b256,
                &nft_hash,
                &sk,
                nonce,
            )?;
            let rows = vec![
                row("NFT Type", "tribute-draft"),
                row("ID", &hex_b256(&entity.id)),
                row("Derived Owner", &out.derived_owner),
                row("Currency", "978"),
            ];
            (out, rows)
        }
    };

    let json = serde_json::to_string_pretty(&generated_output)
        .context("Failed to serialize GeneratedOutput to JSON")?;
    std::fs::write(output, &json)
        .with_context(|| format!("Failed to write output file: {}", output.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(output, permissions)
            .with_context(|| format!("Failed to set file permissions on {}", output.display()))?;
    }

    eprintln!(
        "WARNING: Output file '{}' contains a secret key. Restrict access and do not commit to version control.",
        output.display()
    );
    println!("{}", build_table(&table_rows));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_output(
    nft_type: &str,
    spending_unit: Option<SpendingUnitJson>,
    tribute_draft: Option<TributeDraftJson>,
    nft_id: &B256,
    derived_owner: &B256,
    nft_hash: &Fr,
    sk: &pso_protocol::codec::Secret<PsoV1>,
    nonce: Fr,
) -> Result<GeneratedOutput> {
    Ok(GeneratedOutput {
        warning: "This file contains a secret key. Do not share or commit to version control."
            .to_string(),
        nft_type: nft_type.to_string(),
        spending_unit,
        tribute_draft,
        nft_id: hex_b256(nft_id),
        derived_owner: hex_b256(derived_owner),
        nft_hash: format!("0x{}", hex::encode(PsoV1::field_to_be_bytes(nft_hash))),
        secret_key_hex: hex::encode(PsoV1::secret_to_bytes(sk).context("secret_to_bytes")?),
        nonce_hex: hex::encode(PsoV1::field_to_be_bytes(&nonce)),
    })
}

fn field_b256(rng: &mut StdRng) -> B256 {
    let f = Fr::rand(rng);
    B256::from_slice(&PsoV1::field_to_be_bytes(&f))
}

fn rand_address(rng: &mut OsRng) -> Address {
    let mut bytes = [0u8; 20];
    rng.fill_bytes(&mut bytes);
    Address::from(bytes)
}

fn hex_b256(b: &B256) -> String {
    format!("0x{}", hex::encode(b))
}

fn row(field: &str, value: &str) -> KeyValueRow {
    KeyValueRow {
        field: field.to_string(),
        value: value.to_string(),
    }
}
