//! ZK witness builders (Grumpkin/Schnorr era).
//!
//! Production home for the witness-generation helpers used by the
//! wallet stack. Per the sec. 4.2 redesign the in-circuit signing
//! curve is Grumpkin (Schnorr), not secp256k1 (ECDSA). Off-chain
//! Schnorr signing lives in [`pso_zk_circuit_noir::schnorr_grumpkin`]
//! (`barretenberg-rs` FFI); this crate just wires those primitives
//! into the [`OwnershipWitness`] / [`FullProofWitness`] structs
//! defined in `pso-protocol`.
//!
//! ## Surface
//!
//! - [`OwnershipWitnessCtx`], [`FullProofWitnessCtx`] -- context
//!   structs taking a `GrumpkinKey` + nonce.
//! - [`build_ownership_witness`], [`build_full_proof_witness`] --
//!   free functions over `T: OwnableNFT (+ HashableNFT)`.
//! - [`FlatAggregationSlot`], [`build_flat_aggregation_witness`] --
//!   helper for assembling the witness vector for the
//!   `pso-flat-aggregation-circuit-n{N}` family. Returns a
//!   `Vec<pso_zk_circuit_noir::FieldElement>` already in the order the circuit's
//!   `main()` expects, ready to feed to `pso_zk_circuit_noir::prove_ultra_honk_keccak`.
//!
//! ## ECDH compatibility
//!
//! The App. A shared-secret derivation still runs on secp256k1
//! (`sk_consent` stays a secp256k1 key for wallet interop). Only the
//! Schnorr signing key is Grumpkin -- the HKDF output is reduced
//! `mod q_Grumpkin` to land a Grumpkin scalar. See the spec sec.
//! 2.2.3 "Curve choice" subsection.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use pso_protocol::merkle::MerklePathElement;
use pso_protocol::witness::{
    FullProofPrivateInputs, FullProofPublicInputs, FullProofWitness, HashableNFT, OwnableNFT,
    OwnershipPrivateInputs, OwnershipPublicInputs, OwnershipWitness,
};

pub use pso_zk_circuit_noir::schnorr_grumpkin::{
    derive_grumpkin_public_key, random_grumpkin_key, schnorr_sign_be, GrumpkinKey,
};

// =====================================================================
// Encoding helpers
// =====================================================================

/// Encode an `Fr` as 32 little-endian bytes (right-padded with zeros).
pub fn fr_to_le32(value: &Fr) -> [u8; 32] {
    let le = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let n = le.len().min(32);
    out[..n].copy_from_slice(&le[..n]);
    out
}

/// Encode an `Fr` as 32 big-endian bytes (left-padded with zeros).
///
/// Use this at the on-chain `bytes32` boundary (e.g. `derivedOwner`
/// stored in SU/TD storage). The barretenberg-emitted public inputs
/// and the `0x0212` SU-hash precompile both treat the slot as BE; if
/// callers store the LE encoding, the precompile reads a totally
/// different Fr and the aggregation proof's public-input prefix
/// won't match the on-chain reconstruction.
pub fn fr_to_be32(value: &Fr) -> [u8; 32] {
    let be = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let off = 32 - be.len().min(32);
    out[off..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    out
}

/// Reduce raw 32-byte input (e.g. an HKDF output) modulo the Grumpkin
/// scalar field order so it's a valid Grumpkin secret key.
///
/// The Grumpkin scalar field is BN254's base field `Fq`. Bare
/// `barretenberg-rs`/`schnorr_compute_public_key` since the bb 5.x
/// bump rejects (with an uncatchable C++ exception that aborts the
/// process) inputs `>= q_Grumpkin`. App. A ECDH/HKDF outputs are
/// uniform over `[0, 2^256)`, so ~63% of unreduced outputs trip that
/// path. Every caller that feeds an external random source into
/// `derive_grumpkin_public_key` must run it through here first.
pub fn reduce_to_grumpkin_sk(bytes: &[u8; 32]) -> [u8; 32] {
    use ark_bn254::Fq;
    let reduced = Fq::from_be_bytes_mod_order(bytes);
    let be = reduced.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let off = 32 - be.len().min(32);
    out[off..].copy_from_slice(&be[be.len().saturating_sub(32)..]);
    out
}

// =====================================================================
// Witness contexts
// =====================================================================

/// Context for generating an ownership-only witness per sec. 4.2.
pub struct OwnershipWitnessCtx<'a> {
    /// Wallet's Grumpkin keypair. For SU ownership this is derived
    /// from the App. A shared secret (HKDF output mod `q_Grumpkin`);
    /// for TD ownership this is a fresh wallet-rolled Grumpkin
    /// keypair generated per Tribute Draft.
    pub key: &'a GrumpkinKey,
    /// Per-NFT nonce baked into the ownership commitment.
    pub nonce: Fr,
    /// Per-NFT entity hash. The signature is over `Poseidon2(nft_hash,
    /// nonce).to_be_bytes()` so the proof is bound to a specific NFT
    /// and can't be replayed across SUs.
    pub nft_hash: Fr,
}

/// Context for generating a full proof witness (ownership + inclusion).
pub struct FullProofWitnessCtx<'a> {
    pub key: &'a GrumpkinKey,
    pub nonce: Fr,
    pub merkle_path: &'a [MerklePathElement],
}

// =====================================================================
// Single-SU witness builders
// =====================================================================

/// Build an `OwnershipWitness` per sec. 4.2 of the privacy-preserving
/// L2 spec.
///
/// The signature is `Schnorr_Grumpkin(Poseidon2(nft_hash,
/// nonce).to_be_bytes(), key.sk)`. The 32-byte `(pk.x, pk.y)` bytes
/// encoded into `OwnershipPrivateInputs` are BE Fr encodings (per
/// pso-protocol v0.3 — the witness map serialiser in
/// `pso-zk-circuit-noir` decodes them via
/// `FieldElement::from_be_bytes_reduce`).
pub fn build_ownership_witness<T: OwnableNFT + ?Sized>(
    nft: &T,
    ctx: OwnershipWitnessCtx<'_>,
) -> anyhow::Result<OwnershipWitness> {
    let ownership_fr = nft.ownership();
    let ownership = fr_to_be32(&ownership_fr);

    let prehash_fr = pso_protocol::hash::poseidon2(ctx.nft_hash, ctx.nonce)
        .map_err(|e| anyhow::anyhow!("poseidon2(nft_hash, nonce): {e}"))?;
    let signature = schnorr_sign_be(&ctx.key.sk_bytes, &prehash_fr)?;

    Ok(OwnershipWitness {
        private_inputs: OwnershipPrivateInputs {
            nonce: fr_to_be32(&ctx.nonce),
            public_key_x: fr_to_be32(&ctx.key.pk_x),
            public_key_y: fr_to_be32(&ctx.key.pk_y),
        },
        public_inputs: OwnershipPublicInputs {
            ownership,
            nft_hash: fr_to_be32(&ctx.nft_hash),
            signature,
        },
    })
}

/// Build a `FullProofWitness` from any `OwnableNFT + HashableNFT`.
/// Same per-SU ownership semantics as [`build_ownership_witness`],
/// composed with a Merkle-inclusion check on the same `nft_hash`.
pub fn build_full_proof_witness<T: OwnableNFT + HashableNFT + ?Sized>(
    nft: &T,
    ctx: FullProofWitnessCtx<'_>,
) -> anyhow::Result<FullProofWitness> {
    let ownership_fr = nft.ownership();
    let ownership = fr_to_be32(&ownership_fr);

    let nft_hash_fr = nft.hash().map_err(|e| anyhow::anyhow!("nft hash: {e}"))?;
    let nft_hash = fr_to_be32(&nft_hash_fr);

    let prehash_fr = pso_protocol::hash::poseidon2(nft_hash_fr, ctx.nonce)
        .map_err(|e| anyhow::anyhow!("poseidon2(nft_hash, nonce): {e}"))?;
    let signature = schnorr_sign_be(&ctx.key.sk_bytes, &prehash_fr)?;

    let merkle_root_fr = pso_protocol::merkle::compute_merkle_root(
        &nft_hash_fr,
        ctx.merkle_path,
        pso_protocol::merkle::SPARSE_MERKLE_PATH_DEPTH,
    )
    .map_err(|e| anyhow::anyhow!("merkle root: {e}"))?;
    let merkle_root = fr_to_be32(&merkle_root_fr);

    Ok(FullProofWitness {
        private_inputs: FullProofPrivateInputs {
            ownership: OwnershipPrivateInputs {
                nonce: fr_to_be32(&ctx.nonce),
                public_key_x: fr_to_be32(&ctx.key.pk_x),
                public_key_y: fr_to_be32(&ctx.key.pk_y),
            },
            merkle_path: ctx.merkle_path.to_vec(),
        },
        public_inputs: FullProofPublicInputs {
            ownership: OwnershipPublicInputs {
                ownership,
                nft_hash,
                signature,
            },
            merkle_root,
        },
    })
}

// =====================================================================
// Flat aggregation witness
// =====================================================================

/// One slot of a flat-aggregation witness. The wallet supplies as
/// many real slots as it has SUs being aggregated; padded slots
/// (nonce/owner/nft_hash = 0, signature = valid Schnorr over the
/// zero prehash) are inserted by [`build_flat_aggregation_witness`].
#[derive(Debug, Clone, Copy)]
pub struct FlatAggregationSlot {
    /// Grumpkin keypair owning this SU.
    pub key: GrumpkinKey,
    /// Per-SU nonce (the `su_nonce` from the SRA receipt for SU
    /// ownership; baked into the SU's `owner` commitment).
    pub nonce: Fr,
    /// The SU's `derivedOwner` field (Poseidon3 of pk.x, pk.y, nonce).
    pub owner: Fr,
    /// The SU's entity hash (`pso_protocol::nft::compute_spending_unit_hash`).
    pub nft_hash: Fr,
}

/// Build the witness vector for `pso-flat-aggregation-circuit-n{N}`,
/// padded to `tier_n` slots.
///
/// Layout matches the circuit's `main()` parameter order exactly:
/// ```text
///   pk            : [EmbeddedCurvePoint; N]   -> 2N Fr (pk_x_0, pk_y_0, ...)
///   signature     : [[u8; 64]; N]             -> 64N bytes (one Field per byte)
///   nonce         : [Field; N]                -> N Fr
///   public_inputs : pub [Field; 2 * N]        -> 2N Fr (owner_0, nft_hash_0, ...)
/// ```
///
/// Returns a `Vec<pso_zk_circuit_noir::FieldElement>` ready to feed to
/// `pso_zk_circuit_noir::witness::from_vec_to_witness_map`. Caller is responsible
/// for picking the right tier circuit (`pso_zk_canonical::FLAT_AGGREGATION_N{N}`)
/// and `tier_n`.
///
/// Padded slots use `(pk=(0,0), signature=[0;64], nonce=0, owner=0,
/// nft_hash=0)`. The circuit performs identical constraint checks on
/// padded slots, but the chain-side `TributeDraft.submit` zeroes
/// padded `(owner, nft_hash)` pairs at the public-input boundary so
/// they can't be conflated with real SUs.
pub fn build_flat_aggregation_witness(
    real_slots: &[FlatAggregationSlot],
    tier_n: u32,
) -> anyhow::Result<Vec<pso_zk_circuit_noir::FieldElement>> {
    use pso_zk_circuit_noir::{AcirField, FieldElement};

    if (real_slots.len() as u32) > tier_n {
        anyhow::bail!(
            "real slot count {} exceeds tier size {}",
            real_slots.len(),
            tier_n,
        );
    }

    let n = tier_n as usize;
    let mut pk_x_vals = Vec::with_capacity(n);
    let mut pk_y_vals = Vec::with_capacity(n);
    let mut sig_vals = Vec::with_capacity(n * 64);
    let mut nonce_vals = Vec::with_capacity(n);
    let mut owner_vals = Vec::with_capacity(n);
    let mut nft_hash_vals = Vec::with_capacity(n);

    for slot in real_slots {
        pk_x_vals.push(slot.key.pk_x);
        pk_y_vals.push(slot.key.pk_y);
        nonce_vals.push(slot.nonce);
        owner_vals.push(slot.owner);
        nft_hash_vals.push(slot.nft_hash);

        // Sign the binding prehash for this slot.
        let prehash_fr = pso_protocol::hash::poseidon2(slot.nft_hash, slot.nonce)
            .map_err(|e| anyhow::anyhow!("poseidon2(nft_hash, nonce): {e}"))?;
        let sig = schnorr_sign_be(&slot.key.sk_bytes, &prehash_fr)?;
        sig_vals.extend_from_slice(&sig);
    }

    // Pad up to tier_n. For padded slots we need a valid Schnorr
    // signature over `Poseidon2(0, 0).to_be_bytes()` since the circuit
    // runs the same verify on every slot. The signing key for padded
    // slots is a fixed reproducible value -- generated from an
    // all-zero secret would be invalid (sk must be non-zero); the
    // wallet picks any fresh Grumpkin key it likes. Here we generate
    // one fresh padding key per build call.
    let padding_key = if real_slots.len() < n {
        Some(random_grumpkin_key()?)
    } else {
        None
    };

    while pk_x_vals.len() < n {
        let key = padding_key.expect("padding_key Some when more slots needed");
        let nonce = Fr::from(0u64);
        let nft_hash = Fr::from(0u64);
        let owner = pso_protocol::ownership::compute_ownership_grumpkin(key.pk_x, key.pk_y, nonce)
            .map_err(|e| anyhow::anyhow!("compute_ownership_grumpkin(pad): {e}"))?;
        let prehash_fr = pso_protocol::hash::poseidon2(nft_hash, nonce)
            .map_err(|e| anyhow::anyhow!("poseidon2(pad): {e}"))?;
        let sig = schnorr_sign_be(&key.sk_bytes, &prehash_fr)?;

        pk_x_vals.push(key.pk_x);
        pk_y_vals.push(key.pk_y);
        nonce_vals.push(nonce);
        owner_vals.push(owner);
        nft_hash_vals.push(nft_hash);
        sig_vals.extend_from_slice(&sig);
    }

    // Assemble the witness vector in the circuit's main() order.
    let mut witness_vec: Vec<FieldElement> = Vec::with_capacity(2 * n + 64 * n + n + 2 * n);

    // pk: [EmbeddedCurvePoint; N] -> (pk_x_i, pk_y_i) pairs.
    for i in 0..n {
        witness_vec.push(FieldElement::from_le_bytes_reduce(&fr_to_le32(
            &pk_x_vals[i],
        )));
        witness_vec.push(FieldElement::from_le_bytes_reduce(&fr_to_le32(
            &pk_y_vals[i],
        )));
    }
    // signature: [[u8; 64]; N] -> N*64 bytes as Field elements.
    for byte in &sig_vals {
        witness_vec.push(FieldElement::from(*byte as u32));
    }
    // nonce: [Field; N].
    for v in &nonce_vals {
        witness_vec.push(FieldElement::from_le_bytes_reduce(&fr_to_le32(v)));
    }
    // public_inputs: pub [Field; 2 * N] -> interleaved (owner_i, nft_hash_i).
    for i in 0..n {
        witness_vec.push(FieldElement::from_le_bytes_reduce(&fr_to_le32(
            &owner_vals[i],
        )));
        witness_vec.push(FieldElement::from_le_bytes_reduce(&fr_to_le32(
            &nft_hash_vals[i],
        )));
    }

    Ok(witness_vec)
}
