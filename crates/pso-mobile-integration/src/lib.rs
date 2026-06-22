//! Sample FFI — **mobile / wallet** side (Mozilla UniFFI, object-oriented).
//!
//! Object model:
//!   * [`Wallet`] — holds the wallet's entropy seed. Mints a [`Consent`]
//!     ([`Wallet::generate_consent`] / [`Wallet::load_consent`]), generates a
//!     tribute-draft [`NftHeader`] ([`Wallet::generate_nft_header`]), and
//!     aggregates per-NFT ownership witnesses into a tribute-draft proof
//!     ([`Wallet::prove_ownership`]).
//!   * [`Consent`] — a consent keypair. Proves ownership of an issued NFT
//!     ([`Consent::prove_ownership`]) or just builds the ownership witness
//!     ([`Consent::witness`]) for later aggregation. The NFT signing key is
//!     reconstructed inside the consent box and never crosses the boundary.
//!
//! Records carry the data that crosses; the objects carry behavior + state.
//! The "proof" is the mock backend's output (the circuit public inputs) — a
//! real build swaps in the noir backend.

use std::sync::Arc;

use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;

use pso_protocol::primitive::signature::SignatureScheme;
use pso_protocol::protocol::entity::OwnershipReceipt;
use pso_protocol::protocol::zk::{Circuit, ProofGenerator};
use pso_protocol::PsoV1;
use pso_protocol::Suite;
use pso_zk_canonical::aggregation::{AggregationTier, AnyTier, Slot};
use pso_zk_canonical::noir::ownership_proof::{OwnershipProof, PublicInputs, Witness};
use pso_zk_canonical::noir::EmbeddedCurvePoint;
use pso_zk_canonical::ownership::Provable;

use pso_protocol::codec::Secret;
use pso_protocol::protocol::key::SecretScalar;
use pso_protocol::Codec;
use pso_zk_backend::barretenberg::Barretenberg;
use sha2::{Digest, Sha256};

use pso_vdf::minroot::{MinRootProof, MinRootVdf};
use pso_vdf::params::VdfParams;
use pso_vdf::types::{VdfInput, VdfOutput};
use pso_vdf::Vdf;

uniffi::setup_scaffolding!();

type Fr = <PsoV1 as Suite>::Field;

// Sample-only domain separation: the wallet derives distinct deterministic
// keys per purpose from its single seed by flipping a domain byte. Production
// would use proper hierarchical (HD) derivation.
const DOMAIN_CONSENT: u8 = 1;
const DOMAIN_NFT: u8 = 2;
const DOMAIN_SIGN: u8 = 3;
const DOMAIN_PAD: u8 = 4;

/// An NFT issued to a wallet by an attester (the consent-box report the wallet
/// stores). All fields are 32-byte big-endian.
#[derive(Debug, uniffi::Record)]
pub struct IssuanceReport {
    /// NFT id.
    pub nft_id: Vec<u8>,
    /// On-chain `derivedOwner`.
    pub derived_owner: Vec<u8>,
    /// NFT entity hash.
    pub nft_hash: Vec<u8>,
    /// Opaque transcript from the attester, to reconstruct the signer.
    pub opaque_pk: Vec<u8>,
    /// Nonce from the attester, to reconstruct the signer.
    pub nonce: Vec<u8>,
}

/// A locally-generated NFT header for a tribute draft (the draft is itself an
/// NFT, with its own key). Unlike the attester's header this carries the
/// secret key (`nft_sk`), since the wallet owns it. All fields 32-byte BE.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NftHeader {
    /// NFT id.
    pub id: Vec<u8>,
    /// `derivedOwner` commitment.
    pub derived_owner: Vec<u8>,
    /// Signing secret key (Grumpkin scalar).
    pub nft_sk: Vec<u8>,
    /// Ownership nonce.
    pub nonce: Vec<u8>,
}

/// A built ownership witness for one NFT — the serialized circuit slot
/// (`pk`, signature, nonce + the public `owner`/`nft_hash`/`binding`). Produced
/// by [`Consent::witness`], aggregated by [`Wallet::prove_ownership`]. Carries
/// no secret; the signature is already over the shared `binding`.
#[derive(Debug, uniffi::Record)]
pub struct NftOwnershipWitness {
    /// Signing public-key x-coordinate (32 bytes).
    pub pk_x: Vec<u8>,
    /// Signing public-key y-coordinate (32 bytes).
    pub pk_y: Vec<u8>,
    /// 64-byte `s ‖ e` Schnorr signature over the ownership payload.
    pub signature: Vec<u8>,
    /// Ownership nonce (32 bytes).
    pub nonce: Vec<u8>,
    /// `derivedOwner` (32 bytes).
    pub derived_owner: Vec<u8>,
    /// NFT entity hash (32 bytes).
    pub nft_hash: Vec<u8>,
    /// Submission binding the signature commits to (32 bytes).
    pub binding: Vec<u8>,
}

/// A single-NFT ownership proof (mock: `proof` is the concatenated public inputs).
#[derive(Debug, uniffi::Record)]
pub struct ProofResult {
    /// Proof bytes.
    pub proof: Vec<u8>,
    /// Public inputs, each 32-byte big-endian.
    pub public_inputs: Vec<Vec<u8>>,
}

/// A tribute-draft aggregation proof + the canonical circuit it targets.
#[derive(Debug, uniffi::Record)]
pub struct AggregationProofResult {
    /// Slot capacity of the chosen tier (1/2/4/8/16/32/64).
    pub tier_n: u32,
    /// `keccak256(acir)` circuit identity (32 bytes).
    pub circuit_hash: Vec<u8>,
    /// `keccak256(vk)` (32 bytes).
    pub vk_hash: Vec<u8>,
    /// Proof bytes (mock: the concatenated public inputs).
    pub proof: Vec<u8>,
    /// Public inputs (`2N + 1`), each 32-byte big-endian.
    pub public_inputs: Vec<Vec<u8>>,
}

/// A MinRoot VDF evaluation: the output `y` and its proof `π` (each a 48-byte
/// BLS12-381 Fp element, big-endian).
#[derive(Debug, uniffi::Record)]
pub struct VdfResult {
    /// VDF output `y`.
    pub output: Vec<u8>,
    /// Wesolowski-style proof `π`.
    pub proof: Vec<u8>,
}

/// Snapshot of the VDF parameters compiled into this client.
#[derive(Debug, uniffi::Record)]
pub struct VdfConstants {
    /// Base difficulty `T` (sequential MinRoot iterations).
    pub t_base: u64,
    /// Maximum per-epoch difficulty adjustment, percent.
    pub max_difficulty_adjustment_pct: u64,
    /// Epoch length in L2 blocks.
    pub epoch_length_blocks: u64,
    /// Backward-looking proof-validity window in blocks.
    pub proof_validity_window: u64,
}

/// Errors crossing the mobile FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    /// An input byte buffer had the wrong length, or a key/point failed to decode.
    #[error("invalid input: {detail}")]
    InvalidInput { detail: String },
    /// No aggregation tier fits the witness count, or witnesses disagree.
    #[error("aggregation unavailable: {detail}")]
    AggregationUnavailable { detail: String },
    /// Witness build / proof generation failed (e.g. an owner mismatch).
    #[error("proof generation failed: {detail}")]
    ProofFailed { detail: String },
}

impl From<pso_protocol::error::Error> for MobileError {
    fn from(e: pso_protocol::error::Error) -> Self {
        MobileError::ProofFailed {
            detail: e.to_string(),
        }
    }
}

fn arr<const N: usize>(v: &[u8], what: &str) -> Result<[u8; N], MobileError> {
    v.try_into().map_err(|_| MobileError::InvalidInput {
        detail: format!("{what}: expected {N} bytes, got {}", v.len()),
    })
}

/// Decode an untrusted 32-byte big-endian field element **canonically** —
/// rejecting any value `>=` the field modulus instead of silently reducing it
/// (`field_from_be32`). A non-canonical input has no field element, and
/// reducing it would alias distinct byte strings onto one element, breaking the
/// on-chain ↔ in-circuit binding the proof commits to. Every field-valued input
/// crossing this boundary (a derived owner, an entity hash, a nonce, a binding)
/// goes through here.
fn field32(v: &[u8], what: &'static str) -> Result<Fr, MobileError> {
    let bytes = arr::<32>(v, what)?;
    pso_protocol::codec::field_from_be_bytes_canonical::<Fr>(&bytes, what).map_err(|e| {
        MobileError::InvalidInput {
            detail: e.to_string(),
        }
    })
}

/// A deterministic per-purpose RNG: `StdRng` seeded with `sha256(tag ‖ seed ‖
/// domain)`. The domain tag is **load-bearing**, not cosmetic — each wallet
/// method re-seeds from the *same* root seed, so without it `generate_consent`
/// and `generate_nft_header` would draw the identical stream and the consent key
/// would equal the draft NFT key. The hash is just the KDF that turns one seed
/// into independent per-purpose sub-seeds. Because the seed is hashed it may be
/// any length; sample-only, production wants real hierarchical (HD) derivation.
fn seeded_rng(seed: &[u8], domain: u8) -> StdRng {
    let mut h = Sha256::new();
    h.update(b"pso/wallet/rng/v1");
    h.update(seed);
    h.update([domain]);
    StdRng::from_seed(h.finalize().into())
}

/// Build a per-purpose RNG from a caller-supplied seed buffer. The seed is
/// hashed (see [`seeded_rng`]), so its length is free — we only require a
/// 32-byte (256-bit) entropy floor, not an exact size. Not retained; the caller
/// owns its lifetime.
fn rng_from(seed: &[u8], domain: u8) -> Result<StdRng, MobileError> {
    if seed.len() < 32 {
        return Err(MobileError::InvalidInput {
            detail: format!("seed: expected >= 32 bytes of entropy, got {}", seed.len()),
        });
    }
    Ok(seeded_rng(seed, domain))
}

// ---- proof backend ----
//
// Real UltraHonkKeccak proofs from `pso-zk-backend` (FFI, on-device). The
// returned `proof` is the flat proof bytes; `public_inputs` are the 32-byte BE
// field elements computed from the claim.

/// Ownership-circuit proof bytes for one slot.
fn ownership_proof_bytes(witness: &Witness, public: &PublicInputs) -> Result<Vec<u8>, MobileError> {
    let proof = ProofGenerator::<PsoV1, OwnershipProof>::generate(
        &Barretenberg::default(),
        witness,
        public,
    )?;
    Ok(proof.proof.concat())
}

/// Aggregation proof bytes for a runtime-selected tier.
fn aggregation_proof_bytes(any: &AnyTier) -> Result<Vec<u8>, MobileError> {
    use pso_zk_canonical::noir::{
        flat_aggregation_n1::FlatAggregationN1, flat_aggregation_n16::FlatAggregationN16,
        flat_aggregation_n2::FlatAggregationN2, flat_aggregation_n32::FlatAggregationN32,
        flat_aggregation_n4::FlatAggregationN4, flat_aggregation_n64::FlatAggregationN64,
        flat_aggregation_n8::FlatAggregationN8,
    };
    let bb = Barretenberg::default();
    let proof = match any {
        AnyTier::N1(w, p) => ProofGenerator::<PsoV1, FlatAggregationN1>::generate(&bb, w, p)?,
        AnyTier::N2(w, p) => ProofGenerator::<PsoV1, FlatAggregationN2>::generate(&bb, w, p)?,
        AnyTier::N4(w, p) => ProofGenerator::<PsoV1, FlatAggregationN4>::generate(&bb, w, p)?,
        AnyTier::N8(w, p) => ProofGenerator::<PsoV1, FlatAggregationN8>::generate(&bb, w, p)?,
        AnyTier::N16(w, p) => ProofGenerator::<PsoV1, FlatAggregationN16>::generate(&bb, w, p)?,
        AnyTier::N32(w, p) => ProofGenerator::<PsoV1, FlatAggregationN32>::generate(&bb, w, p)?,
        AnyTier::N64(w, p) => ProofGenerator::<PsoV1, FlatAggregationN64>::generate(&bb, w, p)?,
    };
    Ok(proof.proof.concat())
}

/// A wallet: derives consent + NFT keys from a 32-byte entropy seed and
/// aggregates ownership into tribute-draft proofs. **Stateless** — the seed is
/// not retained, but passed to each operation that needs it and wiped after
/// use, so the root secret never lives in this object.
#[derive(uniffi::Object)]
pub struct Wallet {}

/// SRS G1 point count for the **full proof** — the largest aggregation tier the
/// wallet can submit (n64, the 2^20 proving domain → `(1<<20)+1` points,
/// ~64 MiB). bb's CRS is one-shot, so pre-sizing it to this lets every smaller
/// tier prove from the same setup.
const FULL_PROOF_SRS_POINTS: u32 = (1 << 20) + 1;

#[uniffi::export]
impl Wallet {
    /// Construct a wallet handle (holds no secret).
    ///
    /// Lazy SRS: the first proof sizes/loads the CRS (cache, else — only in a
    /// `with-network-srs` build — a download). On a mobile build (no network
    /// fallback) prefer [`Wallet::new_with_srs`]; otherwise the first proof
    /// errors with "SRS not available … set_srs_path".
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }

    /// Construct a wallet that proves against an **app-provided SRS file** — the
    /// on-device path. `srs_path` is a bundled BN254 G1 `.dat` (the trusted
    /// setup); the prover reads it instead of hitting the network (mobile is
    /// built without the network fallback). The CRS is pre-sized to the full
    /// proof ([`FULL_PROOF_SRS_POINTS`]) so any tribute up to the protocol-max
    /// n64 aggregation proves; the bytes are integrity-checked against the
    /// pinned CRS hash before use, and a missing/short/mismatched file errors
    /// here rather than at first proof.
    #[uniffi::constructor]
    pub fn new_with_srs(srs_path: String) -> Result<Arc<Self>, MobileError> {
        pso_zk_backend::barretenberg::set_srs_path(srs_path.into());
        pso_zk_backend::barretenberg::preinit_srs(FULL_PROOF_SRS_POINTS)?;
        Ok(Arc::new(Self {}))
    }

    /// Compute the submission `binding` the aggregation proof commits to:
    /// `Hash([DOMAIN, sender, tribute_draft_id_lo, _hi, chain_id])` (mirrors
    /// `PsoV1::binding`). The wallet derives this from the tx submitter (the
    /// per-tx opaque key's EOA), the tribute-draft id, and the chain id, then
    /// feeds the SAME `binding` to every [`Consent::witness`] and
    /// [`Wallet::prove_ownership`] call so the proof binds to that exact
    /// submitter + id + chain. `sender_address` is the 20-byte EVM address,
    /// `tribute_draft_id` the 32-byte big-endian id; returns the 32-byte
    /// big-endian field element.
    pub fn compute_binding(
        &self,
        sender_address: Vec<u8>,
        tribute_draft_id: Vec<u8>,
        chain_id: u64,
    ) -> Result<Vec<u8>, MobileError> {
        let sender = arr::<20>(&sender_address, "sender_address")?;
        let commitment_id = arr::<32>(&tribute_draft_id, "tribute_draft_id")?;
        let binding = PsoV1::binding(&sender, &commitment_id, chain_id)?;
        Ok(PsoV1::field_to_be_bytes(&binding))
    }

    /// Derive this wallet's consent keypair (deterministic from `seed`).
    pub fn generate_consent(&self, seed: Vec<u8>) -> Result<Arc<Consent>, MobileError> {
        let mut rng = rng_from(&seed, DOMAIN_CONSENT)?;
        let (sk, _pk) = PsoV1::random_keypair(&mut rng);
        Ok(Arc::new(Consent {
            sk: SecretScalar::new(sk),
        }))
    }

    /// Load a consent from a previously-exported 32-byte secret.
    pub fn load_consent(&self, consent_sk: Vec<u8>) -> Result<Arc<Consent>, MobileError> {
        let sk = PsoV1::secret_from_bytes(&arr::<32>(&consent_sk, "consent_sk")?).map_err(|e| {
            MobileError::InvalidInput {
                detail: e.to_string(),
            }
        })?;
        Ok(Arc::new(Consent {
            sk: SecretScalar::new(sk),
        }))
    }

    /// Generate a fresh tribute-draft NFT header (the draft's own key + owner),
    /// derived from `seed`.
    pub fn generate_nft_header(&self, seed: Vec<u8>) -> Result<NftHeader, MobileError> {
        let mut rng = rng_from(&seed, DOMAIN_NFT)?;
        let (sk, pk) = <PsoV1 as Suite>::Signature::keypair(&mut rng);
        let nonce = Fr::rand(&mut rng);
        let derived_owner = PsoV1::derive_owner(&pk, nonce)?;
        let id = Fr::rand(&mut rng);
        Ok(NftHeader {
            id: PsoV1::field_to_be_bytes(&id),
            derived_owner: PsoV1::field_to_be_bytes(&derived_owner),
            nft_sk: PsoV1::secret_to_bytes(&sk)?.to_vec(),
            nonce: PsoV1::field_to_be_bytes(&nonce),
        })
    }

    /// Aggregate `witnesses` (built by [`Consent::witness`]) over the shared
    /// submission `binding` into a tribute-draft proof. Every witness must
    /// commit to that same `binding`; the smallest fitting tier is chosen and
    /// padded.
    pub fn prove_ownership(
        &self,
        seed: Vec<u8>,
        binding: Vec<u8>,
        witnesses: Vec<NftOwnershipWitness>,
    ) -> Result<AggregationProofResult, MobileError> {
        if witnesses.is_empty() {
            return Err(MobileError::AggregationUnavailable {
                detail: "no witnesses".into(),
            });
        }
        let binding_bytes = arr::<32>(&binding, "binding")?;
        let binding = field32(&binding_bytes, "binding")?;

        let mut slots: Vec<Slot> = Vec::with_capacity(witnesses.len());
        for (i, w) in witnesses.iter().enumerate() {
            if w.binding != binding_bytes {
                return Err(MobileError::AggregationUnavailable {
                    detail: format!("witness {i} commits to a different binding"),
                });
            }
            let witness = Witness {
                pk: EmbeddedCurvePoint {
                    x: field32(&w.pk_x, "pk_x")?,
                    y: field32(&w.pk_y, "pk_y")?,
                },
                signature: arr::<64>(&w.signature, "signature")?,
                nonce: field32(&w.nonce, "nonce")?,
            };
            let public = PublicInputs {
                owner: field32(&w.derived_owner, "derived_owner")?,
                nft_hash: field32(&w.nft_hash, "nft_hash")?,
                binding_hash: binding,
            };
            slots.push((witness, public));
        }

        let tier =
            AggregationTier::for_count(slots.len()).ok_or(MobileError::AggregationUnavailable {
                detail: format!("no aggregation tier for n={} (must be 1..=64)", slots.len()),
            })?;
        let mut rng = rng_from(&seed, DOMAIN_PAD)?;
        let any = tier.assemble::<PsoV1, _>(&mut rng, slots, binding)?;

        let public_inputs: Vec<Vec<u8>> = any
            .public_inputs()
            .iter()
            .map(PsoV1::field_to_be_bytes)
            .collect();
        let proof = aggregation_proof_bytes(&any)?;
        Ok(AggregationProofResult {
            tier_n: tier.capacity() as u32,
            circuit_hash: tier.circuit_hash().to_vec(),
            vk_hash: tier.vk_hash().to_vec(),
            proof,
            public_inputs,
        })
    }

    // ---- MinRoot VDF (proof-of-personhood) ----
    //
    // Wallets attach a VDF proof to every Users-pool tx so the sequencer can
    // rate-limit by sequential-compute cost. Workflow: derive_vdf_input from a
    // fresh L2 height -> compute_vdf on a background thread -> attach output +
    // proof to the tx (broadcast `submitted_block` so the validator re-derives
    // the same input). verify_vdf is the fast self-check before broadcasting.

    /// Construct the canonical 32-byte VDF input the validator expects:
    /// `SHA-256(signer_be_20 ‖ nonce_le_8 ‖ submitted_block_le_8 ‖ chain_id_le_8)`.
    /// The validator rejects any mismatch, so wallets must use this exactly.
    pub fn derive_vdf_input(
        &self,
        signer: Vec<u8>,
        tx_nonce: u64,
        submitted_block: u64,
        chain_id: u64,
    ) -> Result<Vec<u8>, MobileError> {
        let signer = arr::<20>(&signer, "signer")?;
        let input = VdfParams::derive_input_from(signer, tx_nonce, submitted_block, chain_id);
        Ok(input.as_bytes().to_vec())
    }

    /// Compute the MinRoot VDF over `input` with `difficulty` sequential
    /// iterations. **Slow path** — run on a background thread. `input` must be
    /// 32 bytes (typically [`Wallet::derive_vdf_input`]); `difficulty` must be > 0.
    pub fn compute_vdf(&self, input: Vec<u8>, difficulty: u64) -> Result<VdfResult, MobileError> {
        if difficulty == 0 {
            return Err(MobileError::InvalidInput {
                detail: "vdf difficulty must be > 0".into(),
            });
        }
        let input = VdfInput::from_bytes(arr::<32>(&input, "vdf input")?);
        let (output, proof) = MinRootVdf::eval(&input, difficulty);
        Ok(VdfResult {
            output: output.0,
            proof: proof.inner,
        })
    }

    /// Verify a MinRoot VDF proof. **Fast path** (~ms) — the wallet's sanity
    /// check before broadcasting. Returns `true` iff `(output, proof)` proves
    /// `output = MinRoot(input, difficulty)`.
    pub fn verify_vdf(
        &self,
        input: Vec<u8>,
        output: Vec<u8>,
        proof: Vec<u8>,
        difficulty: u64,
    ) -> Result<bool, MobileError> {
        if difficulty == 0 {
            return Err(MobileError::InvalidInput {
                detail: "vdf difficulty must be > 0".into(),
            });
        }
        let input = VdfInput::from_bytes(arr::<32>(&input, "vdf input")?);
        let output = VdfOutput::from_bytes(output);
        let proof = MinRootProof::from_bytes(proof).map_err(|e| MobileError::InvalidInput {
            detail: format!("malformed vdf proof bytes: {e}"),
        })?;
        Ok(MinRootVdf::verify(&input, &output, &proof, difficulty))
    }

    /// Whether `submitted_block` is still within the validator's backward-looking
    /// acceptance `window` relative to `current_block` (so the wallet can reuse a
    /// proof instead of re-running the slow path).
    pub fn is_vdf_block_valid(
        &self,
        submitted_block: u64,
        current_block: u64,
        window: u64,
    ) -> bool {
        VdfParams::is_block_valid(submitted_block, current_block, window)
    }

    /// The VDF parameters compiled into this client (default difficulty, epoch,
    /// validity window).
    pub fn vdf_constants(&self) -> VdfConstants {
        VdfConstants {
            t_base: pso_vdf::T_BASE,
            max_difficulty_adjustment_pct: pso_vdf::MAX_DIFFICULTY_ADJUSTMENT_PCT,
            epoch_length_blocks: pso_vdf::EPOCH_LENGTH_BLOCKS,
            proof_validity_window: pso_vdf::PROOF_VALIDITY_WINDOW,
        }
    }
}

/// A consent keypair: the wallet's long-lived identity an attester issues NFTs
/// to. Holds only the consent secret (encapsulated); the wallet seed used for
/// signing randomness is passed per call, not retained.
#[derive(uniffi::Object)]
pub struct Consent {
    sk: SecretScalar<Secret<PsoV1>>,
}

#[uniffi::export]
impl Consent {
    /// The consent public key to hand an attester for NFT issuance.
    pub fn public_key(&self) -> Result<Vec<u8>, MobileError> {
        Ok(PsoV1::public_key_to_bytes(&PsoV1::public_key_from_secret(self.sk.expose()))?.to_vec())
    }

    /// Export the 32-byte consent secret (e.g. to persist; reload via
    /// [`Wallet::load_consent`]).
    pub fn secret(&self) -> Result<Vec<u8>, MobileError> {
        Ok(PsoV1::secret_to_bytes(self.sk.expose())?.to_vec())
    }

    /// Build the ownership witness for an issued NFT, signed over `binding`.
    /// Reconstructs the signer from the consent material (the NFT secret stays
    /// encapsulated). The witness is self-contained for aggregation.
    pub fn witness(
        &self,
        seed: Vec<u8>,
        report: IssuanceReport,
        binding: Vec<u8>,
    ) -> Result<NftOwnershipWitness, MobileError> {
        let binding_bytes = arr::<32>(&binding, "binding")?;
        let (witness, public) = self.build_ownership(&seed, &report, binding_bytes)?;
        Ok(NftOwnershipWitness {
            pk_x: PsoV1::field_to_be_bytes(&witness.pk.x),
            pk_y: PsoV1::field_to_be_bytes(&witness.pk.y),
            signature: witness.signature.to_vec(),
            nonce: PsoV1::field_to_be_bytes(&witness.nonce),
            derived_owner: PsoV1::field_to_be_bytes(&public.owner),
            nft_hash: PsoV1::field_to_be_bytes(&public.nft_hash),
            binding: binding_bytes.to_vec(),
        })
    }

    /// Prove ownership of one issued NFT (build the witness + run the backend).
    pub fn prove_ownership(
        &self,
        seed: Vec<u8>,
        report: IssuanceReport,
        binding: Vec<u8>,
    ) -> Result<ProofResult, MobileError> {
        let (witness, public) =
            self.build_ownership(&seed, &report, arr::<32>(&binding, "binding")?)?;
        let public_inputs: Vec<Vec<u8>> =
            <OwnershipProof as Circuit<PsoV1>>::public_inputs(&public)
                .iter()
                .map(PsoV1::field_to_be_bytes)
                .collect();
        let proof = ownership_proof_bytes(&witness, &public)?;
        Ok(ProofResult {
            proof,
            public_inputs,
        })
    }
}

// Private helpers — kept OUT of the `#[uniffi::export]` block above because
// that macro exports *every* method in its impl, and `build_ownership`'s types
// (`[u8; 32]`, `(Witness, PublicInputs)`) aren't FFI-representable.
impl Consent {
    /// Reconstruct the signer from the report's consent material and build the
    /// `(Witness, PublicInputs)` ownership pair.
    fn build_ownership(
        &self,
        seed: &[u8],
        report: &IssuanceReport,
        binding: [u8; 32],
    ) -> Result<(Witness, PublicInputs), MobileError> {
        let opaque_pk = PsoV1::public_key_from_bytes(&arr::<32>(&report.opaque_pk, "opaque_pk")?)
            .map_err(|e| MobileError::InvalidInput {
            detail: e.to_string(),
        })?;
        let nonce = field32(&report.nonce, "nonce")?;
        let signer = PsoV1::signer_from_remote(self.sk.expose(), &opaque_pk, nonce)?;
        let receipt = OwnershipReceipt::<PsoV1> {
            id: field32(&report.nft_id, "nft_id")?,
            owner: field32(&report.derived_owner, "derived_owner")?,
            nft_hash: field32(&report.nft_hash, "nft_hash")?,
        };
        let mut rng = rng_from(seed, DOMAIN_SIGN)?;
        Ok(receipt.derive_ownership_witness(&mut rng, &signer, field32(&binding, "binding")?)?)
    }
}

#[cfg(test)]
mod vdf_tests {
    use super::*;

    fn wallet() -> Arc<Wallet> {
        Wallet::new()
    }

    #[test]
    fn derive_input_is_deterministic_and_sensitive() {
        let w = wallet();
        let signer = vec![0xab; 20];
        let base = w
            .derive_vdf_input(signer.clone(), 7, 100, 19_280_501)
            .unwrap();
        assert_eq!(base.len(), 32);
        assert_eq!(
            base,
            w.derive_vdf_input(signer.clone(), 7, 100, 19_280_501)
                .unwrap()
        );
        assert_ne!(
            base,
            w.derive_vdf_input(signer.clone(), 8, 100, 19_280_501)
                .unwrap()
        );
        assert_ne!(
            base,
            w.derive_vdf_input(signer.clone(), 7, 101, 19_280_501)
                .unwrap()
        );
        assert_ne!(
            base,
            w.derive_vdf_input(signer, 7, 100, 19_280_502).unwrap()
        );
    }

    #[test]
    fn derive_input_rejects_wrong_signer_length() {
        assert!(matches!(
            wallet()
                .derive_vdf_input(vec![0u8; 19], 0, 0, 1)
                .unwrap_err(),
            MobileError::InvalidInput { .. }
        ));
    }

    // Tiny difficulty keeps the suite fast; real callers use `T_BASE`.
    #[test]
    fn compute_then_verify_round_trips() {
        let w = wallet();
        let input = w.derive_vdf_input(vec![0xab; 20], 1, 1, 1).unwrap();
        let result = w.compute_vdf(input.clone(), 16).unwrap();
        assert!(!result.proof.is_empty());
        assert!(w
            .verify_vdf(input, result.output, result.proof, 16)
            .unwrap());
    }

    #[test]
    fn verify_rejects_tampered_output() {
        let w = wallet();
        let input = w.derive_vdf_input(vec![0xab; 20], 1, 1, 1).unwrap();
        let mut result = w.compute_vdf(input.clone(), 8).unwrap();
        result.output[0] ^= 0xFF;
        assert!(!w.verify_vdf(input, result.output, result.proof, 8).unwrap());
    }

    #[test]
    fn compute_rejects_zero_difficulty() {
        assert!(matches!(
            wallet().compute_vdf(vec![0u8; 32], 0).unwrap_err(),
            MobileError::InvalidInput { .. }
        ));
    }

    #[test]
    fn block_validity_matches_pso_vdf() {
        let w = wallet();
        assert!(w.is_vdf_block_valid(100, 100, 32));
        assert!(w.is_vdf_block_valid(68, 100, 32));
        assert!(!w.is_vdf_block_valid(67, 100, 32));
        assert!(!w.is_vdf_block_valid(101, 100, 32));
    }
}
