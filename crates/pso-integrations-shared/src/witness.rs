//! k256-aware ZK witness builders.
//!
//! This is the **production** home for the witness-generation helpers
//! that used to live in `pso-zk-core::witness`. They moved here when
//! `pso-protocol` became the consensus-binding layer: `pso-protocol`
//! is deliberately k256-free so on-chain precompiles don't drag in
//! elliptic-curve cryptography. The integration layer keeps the
//! k256-bound pieces.
//!
//! ## Surface
//!
//! - [`ownership_from_secret_key`] — compute the Poseidon5 ownership
//!   commitment from a `SecretKey` + nonce. Mirrors the original
//!   `pso_zk_core::generate_ownership` byte-for-byte.
//! - [`OwnershipWitnessCtx`], [`FullProofWitnessCtx`],
//!   [`AggregationWitnessCtx`] — context structs passed to the
//!   builders.
//! - [`build_ownership_witness`] and [`build_full_proof_witness`] —
//!   free functions over `T: OwnableNFT` (and `+ HashableNFT`).
//!   These would be blanket `GenerateWitness<Ctx>` impls if the orphan
//!   rule allowed it; the trait and `T` are both foreign to this
//!   crate, so we ship them as free functions instead.
//! - [`generate_aggregation_witness`] — free function for the
//!   SU-ownership aggregation circuit (no NFT trait needed).
//! - [`AggregationSlot`] — re-exported from `pso_protocol::witness`
//!   for caller convenience.
//!
//! Every byte layout matches the pre-extraction `pso-zk-core`
//! implementations exactly — the underlying primitives moved, the
//! wire format did not.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{PublicKey, SecretKey};

use pso_protocol::merkle::MerklePathElement;
use pso_protocol::witness::{
    AggregationPrivateInputs, AggregationPublicInputs, AggregationWitness, FullProofPrivateInputs,
    FullProofPublicInputs, FullProofWitness, HashableNFT, OwnableNFT, OwnershipPrivateInputs,
    OwnershipPublicInputs, OwnershipWitness,
};

pub use pso_protocol::witness::AggregationSlot;

// =====================================================================
// Small byte / signing helpers
// =====================================================================

/// Encode an `Fr` as 32 little-endian bytes (right-padded with zeros).
pub fn fr_to_le32(value: &Fr) -> [u8; 32] {
    let le = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let n = le.len().min(32);
    out[..n].copy_from_slice(&le[..n]);
    out
}

/// Extract the SEC1 (uncompressed) x/y coordinates of a `PublicKey`
/// as 32-byte big-endian arrays.
pub fn sec1_coords(public_key: &PublicKey) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let point = public_key.to_sec1_point(false);
    let x_slice: &[u8] = point
        .x()
        .ok_or_else(|| anyhow::anyhow!("public key missing x coordinate"))?;
    let y_slice: &[u8] = point
        .y()
        .ok_or_else(|| anyhow::anyhow!("public key missing y coordinate"))?;
    let x: [u8; 32] = x_slice
        .try_into()
        .map_err(|_| anyhow::anyhow!("x coordinate must be 32 bytes"))?;
    let y: [u8; 32] = y_slice
        .try_into()
        .map_err(|_| anyhow::anyhow!("y coordinate must be 32 bytes"))?;
    Ok((x, y))
}

/// Compute the Poseidon5 ownership commitment from a `SecretKey` and
/// a nonce. Byte-identical replacement for the old
/// `pso_zk_core::generate_ownership(&public_key, nonce)`.
pub fn ownership_from_secret_key(secret_key: &SecretKey, nonce: Fr) -> anyhow::Result<Fr> {
    ownership_from_public_key(&secret_key.public_key(), nonce)
}

/// Same as [`ownership_from_secret_key`] but takes the `PublicKey`
/// directly, for callers that already have one.
pub fn ownership_from_public_key(public_key: &PublicKey, nonce: Fr) -> anyhow::Result<Fr> {
    let (x, y) = sec1_coords(public_key)?;
    pso_protocol::ownership::compute_ownership(&x, &y, nonce)
        .map_err(|e| anyhow::anyhow!("compute_ownership: {e}"))
}

/// ECDSA-secp256k1 prehash signature over `digest.to_bytes_le()`.
/// Used by every witness builder that needs an ownership-proof or
/// aggregation-binding signature.
pub fn sign_prehash_le(secret_key: &SecretKey, digest: &Fr) -> anyhow::Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(&secret_key.to_bytes())?;
    let prehash = fr_to_le32(digest);
    let sig: Signature = signing_key.sign_prehash(&prehash)?;
    Ok(sig.to_bytes().into())
}

// =====================================================================
// Witness contexts
// =====================================================================

/// Context for generating an ownership-only witness.
pub struct OwnershipWitnessCtx<'a> {
    /// Wallet's secret key.
    pub secret_key: &'a SecretKey,
    /// Nonce baked into the ownership commitment.
    pub nonce: Fr,
}

/// Context for generating a full proof witness (ownership + inclusion).
pub struct FullProofWitnessCtx<'a> {
    /// Wallet's secret key.
    pub secret_key: &'a SecretKey,
    /// Nonce baked into the ownership commitment.
    pub nonce: Fr,
    /// Merkle path of siblings (LE-encoded sibling hashes + side).
    pub merkle_path: &'a [MerklePathElement],
}

/// Context for the SU-ownership aggregation witness.
pub struct AggregationWitnessCtx<'a> {
    /// Wallet's secret key.
    pub secret_key: &'a SecretKey,
    /// Real (nonce, derived_owner) pairs to aggregate. Length must be
    /// `<= tier_n`. Extra slots are zero-padded.
    pub real_slots: &'a [AggregationSlot],
    /// Tier size (one of 1, 2, 4, 6, 8, 16, 32, 64).
    pub tier_n: u32,
    /// Pre-computed `pso_protocol::binding::compute_binding_hash(...)`.
    pub binding_hash: Fr,
}

// =====================================================================
// Witness builders (free functions — orphan rule blocks blanket impls
// since `GenerateWitness` and `T` are both foreign to this crate).
// =====================================================================

/// Build an `OwnershipWitness` from any `OwnableNFT` plus a key
/// material context. Equivalent to the original
/// `nft.generate_witness(OwnershipWitnessCtx { ... })` from
/// `pso-zk-core::witness`.
pub fn build_ownership_witness<T: OwnableNFT + ?Sized>(
    nft: &T,
    ctx: OwnershipWitnessCtx<'_>,
) -> anyhow::Result<OwnershipWitness> {
    let (public_key_x, public_key_y) = sec1_coords(&ctx.secret_key.public_key())?;
    let ownership_fr = nft.ownership();
    let ownership = fr_to_le32(&ownership_fr);
    let signature = sign_prehash_le(ctx.secret_key, &ownership_fr)?;
    let nonce = fr_to_le32(&ctx.nonce);

    Ok(OwnershipWitness {
        private_inputs: OwnershipPrivateInputs {
            nonce,
            public_key_x,
            public_key_y,
        },
        public_inputs: OwnershipPublicInputs {
            ownership,
            signature,
        },
    })
}

/// Build a `FullProofWitness` from any `OwnableNFT + HashableNFT`.
/// Equivalent to the original `nft.generate_witness(FullProofWitnessCtx { ... })`.
pub fn build_full_proof_witness<T: OwnableNFT + HashableNFT + ?Sized>(
    nft: &T,
    ctx: FullProofWitnessCtx<'_>,
) -> anyhow::Result<FullProofWitness> {
    let (public_key_x, public_key_y) = sec1_coords(&ctx.secret_key.public_key())?;
    let ownership_fr = nft.ownership();
    let ownership = fr_to_le32(&ownership_fr);
    let signature = sign_prehash_le(ctx.secret_key, &ownership_fr)?;
    let nonce = fr_to_le32(&ctx.nonce);

    let entity_hash_fr = nft
        .hash()
        .map_err(|e| anyhow::anyhow!("entity hash: {e}"))?;
    let entity_hash = fr_to_le32(&entity_hash_fr);

    let merkle_root_fr = pso_protocol::merkle::compute_merkle_root(
        &entity_hash_fr,
        ctx.merkle_path,
        pso_protocol::merkle::SPARSE_MERKLE_PATH_DEPTH,
    )
    .map_err(|e| anyhow::anyhow!("merkle root: {e}"))?;
    let merkle_root = fr_to_le32(&merkle_root_fr);

    Ok(FullProofWitness {
        private_inputs: FullProofPrivateInputs {
            ownership: OwnershipPrivateInputs {
                nonce,
                public_key_x,
                public_key_y,
            },
            merkle_path: ctx.merkle_path.to_vec(),
        },
        public_inputs: FullProofPublicInputs {
            ownership: OwnershipPublicInputs {
                ownership,
                signature,
            },
            entity_hash,
            merkle_root,
        },
    })
}

// =====================================================================
// Aggregation witness — free function (no NFT trait needed)
// =====================================================================

/// Build the SU-ownership aggregation witness.
///
/// Fills `nonces` and `derived_owners` from `ctx.real_slots`, then
/// zero-pads up to `ctx.tier_n`. Signs `binding_hash.to_bytes_le()`
/// with secp256k1 ECDSA (prehash mode) — the same convention the
/// aggregation circuit expects.
pub fn generate_aggregation_witness(
    ctx: AggregationWitnessCtx,
) -> anyhow::Result<AggregationWitness> {
    if (ctx.real_slots.len() as u32) > ctx.tier_n {
        anyhow::bail!(
            "real slot count {} exceeds tier size {}",
            ctx.real_slots.len(),
            ctx.tier_n,
        );
    }

    let (public_key_x, public_key_y) = sec1_coords(&ctx.secret_key.public_key())?;

    let n = ctx.tier_n as usize;
    let mut nonces: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut derived_owners: Vec<[u8; 32]> = Vec::with_capacity(n);
    for slot in ctx.real_slots {
        nonces.push(fr_to_le32(&slot.nonce));
        derived_owners.push(fr_to_le32(&slot.derived_owner));
    }
    while nonces.len() < n {
        nonces.push([0u8; 32]);
        derived_owners.push([0u8; 32]);
    }

    let signature = sign_prehash_le(ctx.secret_key, &ctx.binding_hash)?;

    Ok(AggregationWitness {
        private_inputs: AggregationPrivateInputs {
            public_key_x,
            public_key_y,
            nonces,
            signature,
        },
        public_inputs: AggregationPublicInputs {
            derived_owners,
            binding_hash: fr_to_le32(&ctx.binding_hash),
        },
    })
}
