// `alloy::sol!` expands into many-argument functions that exceed
// clippy's default 7-arg threshold; silence at module scope.
#![allow(clippy::too_many_arguments)]

//! Inline Solidity ABI bindings for the four contracts SRAs and wallets
//! interact with.
//!
//! Declared with `alloy::sol!` against the production interfaces in
//! `psonet/pso-chain` (`contracts/src/interfaces/I*.sol`). Mirrored here
//! rather than imported from `pso-chain::pso-contracts` so this crate
//! stays self-contained — pso-integration is the wallet-side repo and
//! must not git-pin pso-chain transitively. When the on-chain interfaces
//! change, update both copies together.
//!
//! Predeployed addresses are taken from
//! `pso-chain::pso_contracts::addresses` and copied here as constants
//! for the same reason. They live at fixed `0x5200…000{4..7}` slots in
//! the genesis bytecode placement.

use alloy::primitives::{address, Address};

/// `SpendingRecord` — soulbound (ERC-721) registry of submitted
/// spending-record ids, owned by the submitting SRA. The registrar
/// calls `submit(srId)` for each record.
pub const SPENDING_RECORD: Address = address!("5200000000000000000000000000000000000004");

/// `AmendmentRecord` — soulbound (ERC-721) registry of amendment-record
/// ids for spending records, owned by the submitting SRA. Same
/// interface shape as `SpendingRecord` (`submit(arId)`).
pub const AMENDMENT_RECORD: Address = address!("5200000000000000000000000000000000000005");

/// `SpendingUnit` — **commitment token** linking spending records into a
/// spending unit. It has no holder: the SRA registrar calls `submit(...)`
/// with the wallet-supplied `derivedOwner` Poseidon commitment, and
/// ownership is later proven via the `zk_verify` precompile.
pub const SPENDING_UNIT: Address = address!("5200000000000000000000000000000000000006");

/// `TributeDraft` — **commitment token** aggregating multiple spending
/// units. The wallet calls `submit(tdId, derivedOwner, suIds, aggregationProof)`.
pub const TRIBUTE_DRAFT: Address = address!("5200000000000000000000000000000000000007");

/// `SequencerEpoch` — read-only view of the per-epoch leader rotation.
/// Predeployed alongside SRARegistry; testsuite hits this for S038.
pub const SEQUENCER_EPOCH: Address = address!("5200000000000000000000000000000000000002");

/// `SlashingVerifier` — accepts equivocation / offline / withholding /
/// invalid-VDF proofs. Predeployed alongside SequencerEpoch; testsuite
/// hits this for the slashing happy-path scenarios.
pub const SLASHING_VERIFIER: Address = address!("5200000000000000000000000000000000000003");

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISpendingRecord {
        event Submitted(address indexed submitter, uint256 indexed id);
        function submit(uint256 srId) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface IAmendmentRecord {
        event Submitted(address indexed submitter, uint256 indexed id);
        function submit(uint256 arId) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISpendingUnit {
        event Submitted(
            address indexed submitter,
            bytes32 indexed derivedOwner,
            uint256 indexed id,
            uint32 worldwideDay,
            uint64 amountBase,
            uint64 amountAtto,
            uint16 currency
        );
        function submit(
            uint256 suId,
            bytes32 derivedOwner,
            address referrerAddress,
            uint16 currency,
            uint32 worldwideDay,
            uint64 amountBase,
            uint64 amountAtto,
            uint256[] memory srIds,
            uint256[] memory arIds
        ) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ITributeDraft {
        event Submitted(
            address indexed minter,
            bytes32 indexed derivedOwner,
            uint256 indexed id,
            uint32 worldwideDay,
            uint64 amountBase,
            uint64 amountAtto,
            uint16 currency,
            uint256[] suIds
        );
        function submit(
            uint256 tributeDraftId,
            bytes32 derivedOwner,
            uint256[] calldata suIds,
            bytes calldata aggregationProof
        ) external;
    }

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
