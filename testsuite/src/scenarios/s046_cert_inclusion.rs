//! S046 — cert-backed TributeDraft inclusion (SIG-INCLUSION), verified
//! end-to-end off-chain.
//!
//! Submits a real TributeDraft (full aggregation proof, S001's happy path),
//! then proves — without trusting any single node — that the TD is committed
//! and committee-signed:
//!
//! 1. Read the `(treeId, leafIndex, leaf)` the contract inserted from the
//!    `LeafInserted` event in the submit receipt.
//! 2. `pso_getInclusionPath` → the depth-32 co-path + root `R_M` at a finalized
//!    block. Recompute the root from `(leaf, leafIndex, siblings)` with
//!    `pso-protocol`'s Poseidon2 IMT and assert it reproduces `R_M` — the FULL
//!    Merkle proof.
//! 3. `pso_getFinalizeCert(M)` → the committee finalize certificate + the block
//!    digest preimage. The block anchors its IMT root as `r`, so assert
//!    `preimage.r == R_M`, then recompute the committee-signed digest
//!    `SHA256(contextEncoded ‖ parent ‖ height ‖ timestampMs ‖ payloadHash ‖ r)`
//!    and assert it equals `tipDigest` — binding `R_M` into what was signed.
//! 4. Verify the threshold BLS signature over that digest against the group
//!    public key read from the L1 `DaInbox` (the on-chain source of truth) —
//!    so a pass means ≥2f+1 of the committee signed a block that commits `R_M`.
//!
//! Needs `--l1-rpc-url` + `--da-inbox` (for the group key) and the node serving
//! inclusion paths; filtered out in `main` when the L1 isn't wired.

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use alloy_provider::ProviderBuilder;
use alloy_sol_types::{sol, SolEvent};
use alloy_transport_http::reqwest::Url;
use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use pso_chain_abi::addresses::TRIBUTE_DRAFT;
use pso_protocol::protocol::imt::Imt;
use pso_protocol::{Codec, PsoV1, Suite};

use crate::bls_verify::verify_finalize_cert;
use crate::scenarios::s001_happy_flow::submit_full_tribute_draft;
use crate::{Scenario, TestEnv};

type Fr = <PsoV1 as Suite>::Field;

sol! {
    // Emitted by TributeDraft.submit (via CommitmentWindowBase) — NOT part of
    // the thin published ITributeDraft interface, so declared here to decode it.
    event LeafInserted(uint64 indexed treeId, uint64 indexed leafIndex, bytes32 leaf);

    #[sol(rpc)]
    interface IDaInbox {
        // EIP-2537 G2 (256 bytes): the committee group public key the inbox
        // verifies every batch certificate against.
        function groupPubKey() external view returns (bytes);
    }
}

/// How long to wait for the leaf to fold into the finalized inclusion index.
const INCLUSION_TIMEOUT: Duration = Duration::from_secs(120);

pub struct S046;

#[async_trait]
impl Scenario for S046 {
    fn id(&self) -> &'static str {
        "S046"
    }
    fn description(&self) -> &'static str {
        "TD full proof -> inclusion path (Merkle) -> committee-signed root verified vs DaInbox cert"
    }
    async fn run(&self, env: &TestEnv) -> eyre::Result<()> {
        run(env).await
    }
}

async fn run(env: &TestEnv) -> eyre::Result<()> {
    // Group public key lives on L1; without it there's nothing to anchor the
    // committee signature to (main filters S046 out when this is absent).
    let l1_url = env
        .l1_rpc_url
        .as_deref()
        .ok_or_else(|| eyre::eyre!("S046 requires --l1-rpc-url (DaInbox group key)"))?;
    let inbox_addr = env
        .da_inbox
        .ok_or_else(|| eyre::eyre!("S046 requires --da-inbox"))?;

    // 1. Submit a real TD (S001's full happy path) and pull (treeId, leafIndex,
    //    leaf) straight from the LeafInserted event in the receipt.
    let outcome = submit_full_tribute_draft(env).await?;
    let (tree_id, leaf_index, leaf) = leaf_inserted(&outcome.receipt)?;
    let leaf_fr = <PsoV1 as Codec>::field_from_be32(&leaf.0);

    // 2. Poll the node for the inclusion path (pinned to a finalized block) —
    //    the leaf folds into the index a few finalized blocks after submit.
    let actor = env.new_actor()?;
    let incl = poll_inclusion_path(&actor, tree_id, leaf_index).await?;
    let root = json_b256(&incl, "root")?;
    let block_number = json_u64(&incl, "blockNumber")?;
    let siblings = json_siblings(&incl)?;

    // Full Merkle proof: reproduce the root from leaf + co-path.
    let reproduced = Imt::<PsoV1>::root_from_inclusion_path(leaf_fr, leaf_index, &siblings)
        .map_err(|e| eyre::eyre!("S046: root_from_inclusion_path: {e}"))?;
    let root_fr = <PsoV1 as Codec>::field_from_be32(&root.0);
    if reproduced != root_fr {
        return Err(eyre::eyre!(
            "S046: Merkle proof failed — reproduced root != RPC root {root:#x} \
             (treeId={tree_id}, leafIndex={leaf_index})"
        ));
    }

    // 3. Fetch the finalize cert for the pinned block + bind the root into the
    //    committee-signed digest.
    let cert = actor
        .raw_json_rpc("pso_getFinalizeCert", json!([block_number]))
        .await
        .map_err(|e| eyre::eyre!("S046: pso_getFinalizeCert({block_number}): {e:?}"))?;
    let pre = cert
        .get("l2HeaderPreimage")
        .ok_or_else(|| eyre::eyre!("S046: cert missing l2HeaderPreimage"))?;

    // The block anchors its IMT root as `r` — it must equal the path's root.
    let r = json_b256(pre, "r")?;
    if r != root {
        return Err(eyre::eyre!(
            "S046: block r anchor {r:#x} != inclusion root {root:#x} at block {block_number}"
        ));
    }

    // Recompute the signed digest and confirm it binds `r`.
    let parent = json_b256(pre, "parent")?;
    let height = json_u64(pre, "height")?;
    let timestamp_ms = json_u64(pre, "timestampMs")?;
    let payload_hash = json_b256(pre, "payloadHash")?;
    let context_encoded = json_hex(pre, "contextEncoded")?;
    let tip_digest = json_b256(&cert, "tipDigest")?;

    let mut h = Sha256::new();
    h.update(&context_encoded);
    h.update(parent.as_slice());
    h.update(height.to_be_bytes());
    h.update(timestamp_ms.to_be_bytes());
    h.update(payload_hash.as_slice());
    h.update(r.as_slice());
    let digest = B256::from_slice(&h.finalize());
    if digest != tip_digest {
        return Err(eyre::eyre!(
            "S046: recomputed block digest {digest:#x} != cert tipDigest {tip_digest:#x} \
             (the preimage does not bind the root)"
        ));
    }

    // 4. Verify the committee threshold signature over that digest against the
    //    DaInbox group public key (on-chain source of truth).
    let round_epoch = json_u64(&cert, "roundEpoch")?;
    let round_view = json_u64(&cert, "roundView")?;
    let parent_view = json_u64(&cert, "parentView")?;
    let cert_sig = json_hex(&cert, "certSig")?;

    let url: Url = l1_url
        .parse()
        .map_err(|e| eyre::eyre!("S046: invalid --l1-rpc-url {l1_url}: {e}"))?;
    let provider = ProviderBuilder::new().connect_http(url);
    let inbox = IDaInbox::new(inbox_addr, &provider);
    let group_pubkey = inbox
        .groupPubKey()
        .call()
        .await
        .map_err(|e| eyre::eyre!("S046: DaInbox.groupPubKey(): {e}"))?;

    verify_finalize_cert(
        group_pubkey.as_ref(),
        round_epoch,
        round_view,
        parent_view,
        &tip_digest.0,
        &cert_sig,
    )
    .map_err(|e| eyre::eyre!("S046: committee signature over the root did not verify: {e}"))?;

    tracing::info!(
        tree_id,
        leaf_index,
        block_number,
        su_count = outcome.su_ids.len(),
        submitter = %outcome.sender,
        root = %root,
        inbox = %inbox_addr,
        "S046: TD leaf Merkle-proved into a committee-signed IMT root"
    );
    Ok(())
}

/// Find + decode the `LeafInserted(treeId, leafIndex, leaf)` event the
/// TributeDraft emitted in the submit receipt. Shared with S047 (full proof).
pub(crate) fn leaf_inserted(
    receipt: &alloy_rpc_types_eth::TransactionReceipt,
) -> eyre::Result<(u64, u64, B256)> {
    for log in receipt.logs() {
        if log.inner.address != TRIBUTE_DRAFT {
            continue;
        }
        let topics = log.inner.data.topics();
        if topics.first() != Some(&LeafInserted::SIGNATURE_HASH) {
            continue;
        }
        if topics.len() < 3 {
            return Err(eyre::eyre!(
                "S046: LeafInserted has {} topics",
                topics.len()
            ));
        }
        // Indexed uint64 → low 8 bytes of the 32-byte topic (big-endian).
        let tree_id = u64::from_be_bytes(topics[1][24..32].try_into().unwrap());
        let leaf_index = u64::from_be_bytes(topics[2][24..32].try_into().unwrap());
        let data = &log.inner.data.data;
        if data.len() < 32 {
            return Err(eyre::eyre!("S046: LeafInserted data {} bytes", data.len()));
        }
        let leaf = B256::from_slice(&data[..32]);
        return Ok((tree_id, leaf_index, leaf));
    }
    Err(eyre::eyre!(
        "S046: no LeafInserted event from {TRIBUTE_DRAFT:#x} in the TD-submit receipt"
    ))
}

/// Poll `pso_getInclusionPath(treeId, leafIndex, "finalized")` until the leaf
/// has folded into the finalized index (it errors `-32000` until then).
async fn poll_inclusion_path(
    actor: &crate::clients::actor::ActorClient,
    tree_id: u64,
    leaf_index: u64,
) -> eyre::Result<Value> {
    let deadline = Instant::now() + INCLUSION_TIMEOUT;
    let params = json!([tree_id, leaf_index, "finalized"]);
    loop {
        match actor
            .raw_json_rpc("pso_getInclusionPath", params.clone())
            .await
        {
            Ok(v) => return Ok(v),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(eyre::eyre!(
                        "S046: pso_getInclusionPath(treeId={tree_id}, leafIndex={leaf_index}) \
                         not served within {INCLUSION_TIMEOUT:?}: {e:?}"
                    ));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// 32-byte field-element siblings (depth 32, bottom-up) from the RPC result.
fn json_siblings(v: &Value) -> eyre::Result<Vec<Fr>> {
    let arr = v
        .get("siblings")
        .and_then(|x| x.as_array())
        .ok_or_else(|| eyre::eyre!("S046: inclusion path missing siblings[]"))?;
    if arr.len() != 32 {
        return Err(eyre::eyre!("S046: expected 32 siblings, got {}", arr.len()));
    }
    arr.iter()
        .map(|s| {
            let b = parse_hex32(
                s.as_str()
                    .ok_or_else(|| eyre::eyre!("S046: sibling not a string"))?,
            )?;
            Ok(<PsoV1 as Codec>::field_from_be32(&b))
        })
        .collect()
}

fn json_b256(v: &Value, key: &str) -> eyre::Result<B256> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| eyre::eyre!("S046: missing string field `{key}`"))?;
    Ok(B256::from(parse_hex32(s)?))
}

fn json_u64(v: &Value, key: &str) -> eyre::Result<u64> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| eyre::eyre!("S046: missing/non-u64 field `{key}`"))
}

/// Arbitrary-length `0x`-hex field (e.g. `contextEncoded`, `certSig`).
fn json_hex(v: &Value, key: &str) -> eyre::Result<Vec<u8>> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| eyre::eyre!("S046: missing string field `{key}`"))?;
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| eyre::eyre!("S046: `{key}` not hex: {e}"))
}

fn parse_hex32(s: &str) -> eyre::Result<[u8; 32]> {
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| eyre::eyre!("S046: not hex `{s}`: {e}"))?;
    b.as_slice()
        .try_into()
        .map_err(|_| eyre::eyre!("S046: expected 32 bytes, got {}", b.len()))
}
