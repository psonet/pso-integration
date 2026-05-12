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

/// `SpendingRecord` — soulbound NFT registry of submitted spending
/// record hashes. The SRA registrar calls `submit(srId, keys, values)`
/// for each record.
pub const SPENDING_RECORD: Address = address!("5200000000000000000000000000000000000004");

/// `SpendingRecordAmendment` — soulbound NFT registry of amendment
/// hashes for spending records. Same interface shape as
/// `SpendingRecord`.
pub const SPENDING_RECORD_AMENDMENT: Address = address!("5200000000000000000000000000000000000005");

/// `SpendingUnit` — soulbound NFT linking spending records into a
/// spending unit. The SRA registrar calls `submit(...)` after the
/// wallet provides a `derivedOwner` Poseidon commitment.
pub const SPENDING_UNIT: Address = address!("5200000000000000000000000000000000000006");

/// `TributeDraft` — soulbound NFT aggregating multiple spending units.
/// The wallet calls `submit(tdId, derivedOwner, suIds, aggregationProof)`.
pub const TRIBUTE_DRAFT: Address = address!("5200000000000000000000000000000000000007");

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISpendingRecord {
        event Submitted(address indexed submitter, uint256 indexed id);
        function submit(uint256 srId, string[] memory keys, bytes32[] memory values) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISpendingRecordAmendment {
        event Submitted(address indexed submitter, uint256 indexed id);
        function submit(uint256 srId, string[] memory keys, bytes32[] memory values) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISpendingUnit {
        event Submitted(
            address indexed submitter,
            uint256 indexed id,
            bytes32 derivedOwner,
            uint16 settlementCurrency,
            uint32 worldwideDay,
            uint64 settlementAmountBase,
            uint128 settlementAmountAtto,
            uint256[] srIds,
            uint256[] amendmentSrIds
        );
        function submit(
            uint256 suId,
            bytes32 derivedOwner,
            uint16 settlementCurrency,
            uint32 worldwideDay,
            uint64 settlementAmountBase,
            uint128 settlementAmountAtto,
            uint256[] memory srIds,
            uint256[] memory amendmentSrIds
        ) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ITributeDraft {
        event Submitted(
            address indexed submitter,
            bytes32 derivedOwner,
            uint256 indexed tributeDraftId,
            uint32 worldwideDay,
            uint64 settlementAmountBase,
            uint128 settlementAmountAtto,
            uint16 settlementCurrency,
            uint256[] suIds
        );
        function submit(
            uint256 tributeDraftId,
            bytes32 derivedOwner,
            uint256[] calldata suIds,
            bytes calldata aggregationProof
        ) external;
    }
}
