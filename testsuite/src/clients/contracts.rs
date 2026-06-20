//! Inline Solidity bindings for the contracts NOT carried by
//! `pso-chain-abi` — the sequencer-rotation view and the slashing
//! verifier. Their interfaces + proof structs were vendored out of the
//! removed `pso-l2-client::abi` module.
//!
//! Everything else (SpendingRecord / AmendmentRecord / SpendingUnit /
//! TributeDraft / AttestersRegistry) comes from `pso_chain_abi`.

// `alloy_sol_types::sol!` expands into many-argument functions that exceed
// clippy's default 7-arg threshold; silence at module scope.
#![allow(clippy::too_many_arguments)]

use alloy_primitives::{address, Address};

/// `SequencerEpoch` — read-only view of the per-epoch leader rotation.
/// Predeployed alongside the AttestersRegistry; testsuite hits this for
/// S038.
pub const SEQUENCER_EPOCH: Address = address!("5200000000000000000000000000000000000002");

/// `SlashingVerifier` — accepts equivocation / offline / withholding /
/// invalid-VDF proofs. Predeployed alongside SequencerEpoch; testsuite
/// hits this for the slashing happy-path scenarios (S039/S040).
pub const SLASHING_VERIFIER: Address = address!("5200000000000000000000000000000000000003");

alloy_sol_types::sol! {
    /// `SequencerEpoch` — read-only view of the per-epoch leader
    /// rotation. Mirrors `contracts/src/interfaces/ISequencerEpoch.sol`
    /// byte-for-byte (alloy decodes by position, not by name).
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISequencerEpoch {
        function EPOCH_LENGTH() external view returns (uint64);
        function TAKEOVER_DELAY() external view returns (uint64);
        function currentEpoch() external view returns (uint64);
        function leaderForEpoch(uint64 epoch, bytes32 l1AnchorHash)
            external view returns (address);
        function rankedLeadersForEpoch(uint64 epoch, bytes32 l1AnchorHash)
            external view returns (address[] memory);
    }

    /// `SlashingVerifier` — proof-submission surface used by the
    /// slashing happy-path scenarios. Mirrors
    /// `contracts/src/SlashingVerifier.sol` + its `ISlashingVerifier`
    /// interface byte-for-byte.
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISlashingVerifier {
        event Slashed(address indexed sra, uint8 slashType, bytes32 proofHash);
        event EquivocationProven(address indexed sra, uint64 blockNumber);
        event OfflineProven(address indexed sra, uint64 indexed epochNumber, address attestor);
        event BatchWithholdingProven(address indexed sra, uint64 indexed epochNumber, uint256 attestorCount);
        event InvalidVDFProven(address indexed sra);

        struct EquivocationProof {
            bytes32 blockHash1;
            uint64 blockNumber1;
            bytes signature1;
            bytes32 blockHash2;
            uint64 blockNumber2;
            bytes signature2;
        }
        function proveEquivocation(EquivocationProof calldata proof) external;

        struct OfflineProof {
            uint64 epochNumber;
            uint64 silentFromBlock;
            uint64 takenOverAtBlock;
            bytes attestorSignature;
        }
        function proveOffline(OfflineProof calldata proof) external;

        struct BatchWithholdingProof {
            uint64 epochNumber;
            uint64 unsafeHead;
            uint64 safeHead;
            bytes[] attestorSignatures;
        }
        function proveBatchWithholding(BatchWithholdingProof calldata proof) external;

        struct InvalidVDFProof {
            bytes32 vdfInput;
            bytes vdfOutput;
            bytes vdfProof;
            uint64 difficulty;
            address batchSender;
        }
        function proveInvalidVDF(InvalidVDFProof calldata proof) external;

        function proofSubmitted(bytes32 proofHash) external view returns (bool);
    }
}
