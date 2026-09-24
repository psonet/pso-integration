//! Shared material for the enclave-registry / fs-epoch / SU-v2 scenarios
//! (S051–S053), which run in order against one devnet and build on each
//! other's state.
//!
//! What the chain verifies is signatures, not provenance: it never talks to a
//! fingerprint service or a bank-data provider. So the suite can play both
//! parts with keys it generates here — a committee key on BLS12-381 and an
//! enclave key on Ed25519 — and a settlement the chain accepts here is one it
//! would accept from the real thing over the same bytes.
//!
//! The preimages are mirrored from `bdp-seal-codec` (the provider's wire), the
//! same two `SpendingUnitV2.sol` rebuilds. Little-endian integers, `u32le`
//! length prefixes.

use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;

/// The committee's secret, fixed so a rerun against a fresh devnet produces
/// the same epoch 0.
pub const COMMITTEE_SK_IKM: [u8; 32] = [0x51; 32];
/// The successor committee's secret — epoch 1's key, signed by epoch 0's.
pub const COMMITTEE_SK_IKM_NEXT: [u8; 32] = [0x52; 32];
/// The enclave's Ed25519 seed. Its public key is what the admin registers as
/// the deployment's `enclavePk`.
pub const ENCLAVE_SEED: [u8; 32] = [0x53; 32];

/// The committee's hash-to-curve tag, as the fingerprint service states it.
pub const SEAL_DST: &[u8] = b"PSO-FP-v1-SEAL_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// Domain separation of everything the enclave signs.
pub const BDP_DST: &[u8] = b"bdp-enclave-v1";
/// The settlement statement's tag.
pub const TAG_SETTLEMENT: u8 = 0x12;
/// The committee handle's prefix (RFC-0015 v3).
pub const HANDLE_PREFIX: &[u8] = b"bdp-fs-handle-v3";

/// Epoch 0 opens well before any day a scenario uses.
pub const EPOCH0_START_WWD: u32 = 20_200_101;
/// Epoch 1 opens before the batch's day, so the batch belongs to epoch 1.
pub const EPOCH1_START_WWD: u32 = 20_250_101;
/// The batch's worldwide day.
pub const BATCH_WWD: u64 = 20_260_924;

sol! {
    #[sol(rpc)]
    interface IFsEpochRegistry {
        struct Epoch {
            bytes pkAtt;
            bytes dst;
            uint32 startWwd;
            bytes32 membersHash;
            bytes32 prevHash;
        }
        struct SignedEpoch {
            uint32 epoch;
            Epoch entry;
            bytes sigPrev;
        }
        function anchor(Epoch calldata epoch0) external;
        function advance(SignedEpoch[] calldata chain) external;
        function head() external view returns (uint32);
        function anchored() external view returns (bool);
        function digestAt(uint32 e) external view returns (bytes32);
        function digestOf(uint32 e, Epoch calldata entry) external view returns (bytes32);
        function keyFor(uint32 e)
            external
            view
            returns (bytes memory pkAtt, bytes memory dst, uint32 startWwd, uint32 endWwdExclusive);
    }

    #[sol(rpc)]
    interface IEnclaveRegistry {
        function adminRegister(
            bytes32 enclavePk,
            address attester,
            bytes32 rmDigest,
            bytes32 providerId,
            bytes32 baseUrlHash,
            bytes32 measurementHash
        ) external;
        function setMeasurement(bytes32 measurementHash, bool allowed) external;
        function isActiveFor(bytes32 enclavePk, address attester, bytes32 providerId)
            external
            view
            returns (bool);
        function devnetAdminRegister() external view returns (bool);
    }

    #[sol(rpc)]
    interface ISpendingUnitV2 {
        struct Seal {
            bytes32 ctx;
            bytes32 sealId;
            uint32 fsEpoch;
            uint64 worldwideDay;
            uint64 count;
            bytes32 fFold;
            bytes fsGroupKey;
            bytes commitmentRoot;
            uint64 sequence;
        }
        struct Mint {
            uint256 suId;
            bytes32 derivedOwner;
            address referrerAddress;
            bytes32 enclavePk;
            bytes32 providerId;
            uint16 currency;
            uint64 amountBase;
            uint64 amountAtto;
        }
        struct SpendingUnitV2Entity {
            uint256 suId;
            bytes32 derivedOwner;
            address attesterAddress;
            address referrerAddress;
            uint16 currency;
            uint64 worldwideDay;
            uint64 amountBase;
            uint64 amountAtto;
            bytes32 ctx;
            bytes32 sealId;
        }
        function submitSU(
            Mint calldata mint,
            Seal calldata seal,
            bytes calldata handleSigG1,
            bytes calldata settleSig
        ) external;
        function getData(uint256 suId) external view returns (SpendingUnitV2Entity memory);
        function exists(uint256 suId) external view returns (bool);
        function batches(bytes32 ctx) external view returns (bool);
        error AlreadySettled(bytes32 ctx, bytes32 sealId);
    }
}

/// The committee key for an epoch: MinSig, so the key is G2 and the
/// signature G1.
pub fn committee_key(ikm: &[u8; 32]) -> blst::min_sig::SecretKey {
    blst::min_sig::SecretKey::key_gen(ikm, &[]).expect("committee key")
}

/// `pkAtt` in the EIP-2537 layout the registry stores (four 64-byte slots of
/// 16 zero pad ‖ 48-byte coordinate).
pub fn pk_att_eip2537(sk: &blst::min_sig::SecretKey) -> Vec<u8> {
    use blst::{blst_bendian_from_fp, blst_p2_affine, blst_p2_uncompress, BLST_ERROR};

    let compressed = sk.sk_to_pk().compress();
    let mut affine = blst_p2_affine::default();
    let err = unsafe { blst_p2_uncompress(&mut affine, compressed.as_ptr()) };
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS, "uncompress committee key");

    // `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`, each left-padded to 64 bytes.
    let mut out = Vec::with_capacity(256);
    for fp in [
        affine.x.fp[0],
        affine.x.fp[1],
        affine.y.fp[0],
        affine.y.fp[1],
    ] {
        let mut be = [0u8; 48];
        unsafe { blst_bendian_from_fp(be.as_mut_ptr(), &fp) };
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&be);
    }
    out
}

/// A G1 signature in the EIP-2537 layout `submitSU` and `advance` take (two
/// 64-byte slots).
pub fn sig_g1_eip2537(sig: &blst::min_sig::Signature) -> Vec<u8> {
    use blst::{blst_bendian_from_fp, blst_p1_affine, blst_p1_uncompress, BLST_ERROR};

    let compressed = sig.compress();
    let mut affine = blst_p1_affine::default();
    let err = unsafe { blst_p1_uncompress(&mut affine, compressed.as_ptr()) };
    assert_eq!(err, BLST_ERROR::BLST_SUCCESS, "uncompress signature");

    let mut out = Vec::with_capacity(128);
    for fp in [affine.x, affine.y] {
        let mut be = [0u8; 48];
        unsafe { blst_bendian_from_fp(be.as_mut_ptr(), &fp) };
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&be);
    }
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// `HANDLE_PREFIX ‖ attester(20) ‖ ctx ‖ lp(seal_id) ‖ u64le(count) ‖ f_fold
///  ‖ u32le(fs_epoch) ‖ u64le(wwd)` — what the committee signs.
pub fn handle_message(attester: Address, seal: &ISpendingUnitV2::Seal) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDLE_PREFIX.len() + 160);
    out.extend_from_slice(HANDLE_PREFIX);
    out.extend_from_slice(attester.as_slice());
    out.extend_from_slice(seal.ctx.as_slice());
    push_len_prefixed(&mut out, seal.sealId.as_slice());
    out.extend_from_slice(&seal.count.to_le_bytes());
    out.extend_from_slice(seal.fFold.as_slice());
    out.extend_from_slice(&seal.fsEpoch.to_le_bytes());
    out.extend_from_slice(&seal.worldwideDay.to_le_bytes());
    out
}

/// `BDP_DST ‖ 0x12 ‖ ctx ‖ lp(seal_id) ‖ u32le(fs_epoch) ‖ lp(fs_group_key)
///  ‖ rm_digest ‖ lp(commitment_root) ‖ u64le(sequence) ‖ u16le(currency)
///  ‖ u64le(base) ‖ u64le(atto) ‖ u64le(wwd) ‖ u64le(count) ‖ f_fold` — what
/// the enclave signs, and the only statement covering the amount.
pub fn settlement_message(
    mint: &ISpendingUnitV2::Mint,
    seal: &ISpendingUnitV2::Seal,
    rm_digest: B256,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(BDP_DST.len() + 320);
    out.extend_from_slice(BDP_DST);
    out.push(TAG_SETTLEMENT);
    out.extend_from_slice(seal.ctx.as_slice());
    push_len_prefixed(&mut out, seal.sealId.as_slice());
    out.extend_from_slice(&seal.fsEpoch.to_le_bytes());
    push_len_prefixed(&mut out, &seal.fsGroupKey);
    out.extend_from_slice(rm_digest.as_slice());
    push_len_prefixed(&mut out, &seal.commitmentRoot);
    out.extend_from_slice(&seal.sequence.to_le_bytes());
    out.extend_from_slice(&mint.currency.to_le_bytes());
    out.extend_from_slice(&mint.amountBase.to_le_bytes());
    out.extend_from_slice(&mint.amountAtto.to_le_bytes());
    out.extend_from_slice(&seal.worldwideDay.to_le_bytes());
    out.extend_from_slice(&seal.count.to_le_bytes());
    out.extend_from_slice(seal.fFold.as_slice());
    out
}

/// The enclave key the admin registers, and its `enclavePk`.
pub fn enclave_key() -> (ed25519_dalek::SigningKey, B256) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&ENCLAVE_SEED);
    let pk = B256::from(sk.verifying_key().to_bytes());
    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EIP-2537 layout the registry stores is the same key, and the
    /// reverse conversion the DA path already ships reproduces the compressed
    /// bytes exactly. A layout slip here would only surface as a pairing
    /// failure inside a devnet run.
    #[test]
    fn pk_att_eip2537_round_trips() {
        let sk = committee_key(&COMMITTEE_SK_IKM);
        let eip = pk_att_eip2537(&sk);
        assert_eq!(eip.len(), 256, "G2 is four 64-byte slots");
        for slot in eip.chunks(64) {
            assert_eq!(&slot[..16], &[0u8; 16], "each coordinate is 16-byte padded");
        }
        assert_eq!(
            crate::bls_verify::g2_eip2537_to_compressed(&eip).expect("reverse"),
            sk.sk_to_pk().compress(),
            "EIP-2537 → compressed must reproduce the committee key"
        );
    }

    /// The handle signature the contract verifies is the one `blst` verifies
    /// under the same DST, and its EIP-2537 form is two padded slots.
    #[test]
    fn handle_signature_verifies_under_the_epoch_key() {
        use alloy_primitives::keccak256;

        let sk = committee_key(&COMMITTEE_SK_IKM_NEXT);
        let seal = ISpendingUnitV2::Seal {
            ctx: keccak256("ctx"),
            sealId: keccak256("seal"),
            fsEpoch: 1,
            worldwideDay: BATCH_WWD,
            count: 42,
            fFold: keccak256("fold"),
            fsGroupKey: sk.sk_to_pk().compress().to_vec().into(),
            commitmentRoot: keccak256("root").to_vec().into(),
            sequence: 7,
        };
        let message = handle_message(Address::repeat_byte(0xA1), &seal);
        // prefix ‖ 20 ‖ 32 ‖ (4 + 32) ‖ 8 ‖ 32 ‖ 4 ‖ 8
        assert_eq!(message.len(), HANDLE_PREFIX.len() + 140);
        assert!(message.starts_with(HANDLE_PREFIX));

        let sig = sk.sign(&message, SEAL_DST, &[]);
        assert_eq!(
            sig.verify(true, &message, SEAL_DST, &[], &sk.sk_to_pk(), true),
            blst::BLST_ERROR::BLST_SUCCESS,
            "the committee's own verify must accept what we sign"
        );
        let eip = sig_g1_eip2537(&sig);
        assert_eq!(eip.len(), 128, "G1 is two 64-byte slots");
        for slot in eip.chunks(64) {
            assert_eq!(&slot[..16], &[0u8; 16]);
        }
    }

    /// The settlement statement's shape: the tagged frame, the registry's
    /// manifest digest inside it, and the amount covered.
    #[test]
    fn settlement_message_is_the_tagged_statement() {
        use alloy_primitives::keccak256;

        let (sk, enclave_pk) = enclave_key();
        let seal = ISpendingUnitV2::Seal {
            ctx: keccak256("ctx"),
            sealId: keccak256("seal"),
            fsEpoch: 1,
            worldwideDay: BATCH_WWD,
            count: 42,
            fFold: keccak256("fold"),
            fsGroupKey: vec![0u8; 96].into(),
            commitmentRoot: keccak256("root").to_vec().into(),
            sequence: 7,
        };
        let mint = ISpendingUnitV2::Mint {
            suId: alloy_primitives::U256::from(1u64),
            derivedOwner: keccak256("owner"),
            referrerAddress: Address::ZERO,
            enclavePk: enclave_pk,
            providerId: keccak256("mock"),
            currency: 978,
            amountBase: 1_234,
            amountAtto: 5,
        };
        let rm = keccak256("manifest");
        let message = settlement_message(&mint, &seal, rm);

        assert!(message.starts_with(BDP_DST));
        assert_eq!(message[BDP_DST.len()], TAG_SETTLEMENT);
        // The registered manifest digest sits between the key and the root.
        let at = BDP_DST.len() + 1 + 32 + (4 + 32) + 4 + (4 + 96);
        assert_eq!(&message[at..at + 32], rm.as_slice());

        // Changing only the amount changes the statement: that is why the
        // enclave's signature is what binds it.
        let mut louder = mint.clone();
        louder.amountBase += 1;
        assert_ne!(settlement_message(&louder, &seal, rm), message);

        // And the enclave's strict verify accepts its own signature.
        use ed25519_dalek::{Signer as _, Verifier as _};
        let sig = sk.sign(&message);
        sk.verifying_key()
            .verify(&message, &sig)
            .expect("strict verify accepts the enclave's own signature");
    }
}
